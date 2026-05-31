"""Source-reading substrate.

Target lookup (`targets.py`), AST walkers (`ast_python.py`, `ast_ruby.py`),
acquire + index helpers (`acquire.py`, `index.py`), and the cmd_source_* CLI
handlers (`commands.py`).

The AST walker is intra-function taint-flow aware; sink rules check each call
arg against the enclosing function's tainted-local set in addition to the
static UNTRUSTED_VAR_HINTS vocabulary.
"""
