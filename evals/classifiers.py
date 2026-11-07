"""Week 6 experiment: can an open prompt-injection classifier catch malicious skills? (Answer: no, see docs/eval-classifier.md.)

Scores MaliciousSkillBench (all train benign, 1500 sampled train malicious, all test) and every .md file of the real
benign skills with PIGuard and ProtectAI deberta-v3 v2, on a CUDA GPU. 510-token windows, max over the first 4.
Loads weights with standard transformers classes only (PIGuard's repo wants trust_remote_code; it is not run).

  uv run --no-project --python 3.12 --with torch --with "transformers<5" --with sentencepiece --with tokenizers \
    --with pyarrow --with safetensors --with huggingface_hub python evals/classifiers.py scores.json
"""
import csv, json, random, sys, time
from pathlib import Path
import pyarrow.parquet as pq, torch
from huggingface_hub import hf_hub_download
from safetensors.torch import load_file
from tokenizers import Tokenizer
from transformers import DebertaV2Config, DebertaV2ForSequenceClassification, DebertaV2Model

DATA = Path.home() / ".cache/rigseal-eval"
OUT = Path(sys.argv[1])
MAX_CHUNKS = 8  # score 8, so rigseal's 4-chunk limit can be simulated afterwards
dev = "cuda"

PG, PG_REV = "leolee99/PIGuard", "dd78b24e330193a22d2293ac66922dd4f982f563"
PA, PA_REV = "protectai/deberta-v3-base-prompt-injection-v2", "90c9989b1a342275dd0d1a95aad283c04e075671"

class Guard(torch.nn.Module):
    def __init__(self, config):
        super().__init__()
        self.deberta = DebertaV2Model(config)
        self.classifier = torch.nn.Linear(config.hidden_size, config.num_labels)
    def forward(self, input_ids, attention_mask):
        h = self.deberta(input_ids=input_ids, attention_mask=attention_mask).last_hidden_state
        return self.classifier(h[:, 0, :])

def piguard():
    cfg = json.loads(Path(hf_hub_download(PG, "config.json", revision=PG_REV)).read_text())
    for k in ("auto_map", "architectures"): cfg.pop(k, None)
    cfg["model_type"] = "deberta-v2"
    m = Guard(DebertaV2Config.from_dict(cfg))
    state = load_file(hf_hub_download(PG, "model.safetensors", revision=PG_REV))
    missing, _ = m.load_state_dict({k: v for k, v in state.items() if not k.startswith("pooler.")}, strict=False)
    assert not [k for k in missing if not k.endswith("position_ids")], missing
    tok = Tokenizer.from_file(hf_hub_download(PG, "tokenizer.json", revision=PG_REV))
    return m.eval().to(dev), tok, lambda out: out

def protectai():
    m = DebertaV2ForSequenceClassification.from_pretrained(PA, revision=PA_REV)
    tok = Tokenizer.from_file(hf_hub_download(PA, "onnx/tokenizer.json", revision=PA_REV))
    return m.eval().to(dev), tok, lambda out: out.logits

@torch.no_grad()
def score(model, text):
    m, t, logits_of = model
    cls, sep = t.token_to_id("[CLS]"), t.token_to_id("[SEP]")
    ids = t.encode(text, add_special_tokens=False).ids or [0]
    chunks = [[cls] + ids[i:i + 510] + [sep] for i in range(0, len(ids), 510)][:MAX_CHUNKS]
    L = max(map(len, chunks))
    inp = torch.tensor([c + [0] * (L - len(c)) for c in chunks], device=dev)
    mask = torch.tensor([[1] * len(c) + [0] * (L - len(c)) for c in chunks], device=dev)
    p = torch.softmax(logits_of(m(input_ids=inp, attention_mask=mask)).float(), dim=1)[:, 1]
    return [round(float(x), 6) for x in p]  # per chunk

split = {r["benchmark_id"]: r["split"] for r in csv.DictReader(open(DATA / "msb/splits/source_disjoint.csv"))}
tb = pq.read_table(DATA / "msb/primary.parquet", columns=["benchmark_id", "label", "skill_text", "public_skill_text"]).to_pylist()
rng = random.Random(7)
train_mal = [r for r in tb if split.get(r["benchmark_id"]) == "train" and r["label"] == "1"]
keep = {r["benchmark_id"] for r in rng.sample(train_mal, 1500)}
docs = []
for r in tb:
    sp = split.get(r["benchmark_id"]); text = r["skill_text"] or r["public_skill_text"]
    if not text: continue
    if sp == "test" or (sp == "train" and (r["label"] == "0" or r["benchmark_id"] in keep)):
        docs.append({"id": r["benchmark_id"], "split": sp, "label": int(r["label"]), "text": text})
for name in ("anthropics-skills", "obra-superpowers"):
    for p in sorted((DATA / "benign" / name).rglob("*.md")):
        if ".git" in p.parts: continue
        docs.append({"id": str(p.relative_to(DATA)), "split": "real", "label": 0, "text": p.read_text(errors="replace")})
print(f"{len(docs)} docs", flush=True)
results = {}
for name, load in (("protectai", protectai), ("piguard", piguard)):
    model = load(); t0 = time.time()
    for i, d in enumerate(docs):
        results.setdefault(d["id"], {k: d[k] for k in ("split", "label")})[name] = score(model, d["text"])
        if i % 500 == 0: print(f"{name} {i}/{len(docs)} {time.time() - t0:.0f}s", flush=True)
    print(f"{name} done {time.time() - t0:.0f}s", flush=True)
    del model; torch.cuda.empty_cache()
OUT.write_text(json.dumps(results))

# Threshold from the train split's benign false-alarm rate; report test and real skills at that threshold.
def top(d, m): return max(d[m][:4])
def rate(xs, t): return sum(x >= t for x in xs) / max(1, len(xs))
for m in ("protectai", "piguard"):
    group = lambda sp, lab: [top(d, m) for d in results.values() if d["split"] == sp and d["label"] == lab]
    tb = sorted(group("train", 0), reverse=True)
    for target in (0.005, 0.01, 0.02, 0.05):
        t = tb[int(len(tb) * target)] + 1e-9
        real = group("real", 0)
        print(f"{m} train-fa<={target:.1%} thr={t:.4f} train-recall={rate(group('train', 1), t):.1%} "
              f"test-recall={rate(group('test', 1), t):.1%} test-fa={rate(group('test', 0), t):.1%} "
              f"real-fa={sum(x >= t for x in real)}/{len(real)}")
