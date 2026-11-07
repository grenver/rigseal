# Week 6 experiment: prompt-injection classifiers

Question: would an open prompt-injection classifier (planned rule R19) catch malicious skills that the rules miss?
Answer: no. R19 was not shipped.

Run 2026-11-08 on an RTX 3070, fp32. Each text is split into 510-token windows and scored on the first 4; the score is the max.
Thresholds were set on the `train` split so that at most 1% of its 1521 benign skills are flagged, then applied to `test`.

| Model | Threshold | Test recall (of 839 malicious) | Test false alarms (of 545 benign) | Real skill files flagged (of 250 .md) |
|---|---|---|---|---|
| [protectai/deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) `90c9989b` | 0.9971 | 0.0% (0) | 0.2% (1) | 0 |
| [leolee99/PIGuard](https://huggingface.co/leolee99/PIGuard) `dd78b24e` | 0.9975 | 11.9% (100) | 18.5% (101) | 9 |

At a looser 5% train false-alarm budget, ProtectAI reaches 1.0% test recall (2.0% false alarms) and PIGuard 12.6% (22.9%).
PIGuard flags benign skills more often than malicious ones on `test`, so it adds noise, not signal.

Why: these models are trained on chat-style injections ("ignore previous instructions"). Malicious skills in
MaliciousSkillBench mostly read like normal instructions that ask for harmful steps (run this installer, send this
file), which is a judgement about intent, not a text pattern. That is the local judge's job (week 8).

Also: int8 dynamic quantization broke both models (a 0.999 score became 0.099), so a shipped classifier would be a ~740 MB fp32 download.

Reproduce: `evals/classifiers.py` (needs a CUDA GPU and the data from `evals/fetch.py`; the command is in its docstring).
