from rigseal.collectors import claude_code, codex, cursor, shared, vscode

COLLECTORS = [claude_code.collect, codex.collect, cursor.collect, vscode.collect, shared.collect]
AGENTS_OF = {
    claude_code.collect: (claude_code.AGENT,),
    codex.collect: (codex.AGENT,),
    cursor.collect: (cursor.AGENT,),
    vscode.collect: (vscode.VSCODE, vscode.COPILOT),
    shared.collect: (shared.AGENT,),
}
