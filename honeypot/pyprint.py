"""`python3 -c CODE` where CODE only prints constant expressions: `print(2**64)`,
`print("a" * 3, 7 / 2)`. A classic test of a language-model honeypot, because a model
gets long arithmetic wrong; here it is computed, as the real interpreter would.

The answer is Python's own: the relay runs on the gateway's Python 3.13.5, the version of
the reference machine (Debian 13's python3 3.13.5), so str() of an int, a float or a
string is that interpreter's. Nothing is executed: the code is parsed, and only a small
set of constant operations is evaluated, with sizes bounded so that nothing can take
long or use much memory. Anything else (a name, an import, a call other than print, a
keyword argument, an error the real one would print a traceback for, a number too big
for str()) returns None, and the line goes to the model as before."""
from __future__ import annotations
import ast
import math
import operator

# The reference machine's interpreter (offline/gt-installed.txt: python3.13 3.13.5-2),
# for `python3 --version`.
VERSION = "3.13.5"
MAX_DIGITS = 4000           # Python 3.13 refuses str() of an int over 4300 digits
MAX_TEXT = 100_000          # the longest string a line may build
_BIN = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
        ast.Div: operator.truediv, ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod,
        ast.Pow: operator.pow}
_UN = {ast.USub: operator.neg, ast.UAdd: operator.pos}


class _No(Exception):
    pass


def _digits(v: int) -> float:
    return math.log10(abs(v)) + 1 if v else 1


def _value(n: ast.AST):
    if isinstance(n, ast.Constant) and type(n.value) in (int, float, str, bool) or \
            isinstance(n, ast.Constant) and n.value is None:
        if isinstance(n.value, int) and _digits(n.value) > MAX_DIGITS:
            raise _No
        return n.value
    if isinstance(n, ast.UnaryOp) and type(n.op) in _UN:
        v = _value(n.operand)
        if type(v) not in (int, float):
            raise _No
        return _UN[type(n.op)](v)
    if isinstance(n, ast.BinOp) and type(n.op) in _BIN:
        a, b, op = _value(n.left), _value(n.right), type(n.op)
        ta, tb = type(a), type(b)
        if ta in (int, float) and tb in (int, float):
            if op is ast.Pow:
                if ta is int and tb is int:
                    if b < 0 or b > 100_000 or (abs(a) > 1 and b * math.log10(abs(a)) > MAX_DIGITS):
                        raise _No
                elif abs(b) > 1000 or a < 0:          # complex results, overflow
                    raise _No
            elif op is ast.Mult and ta is int and tb is int and _digits(a) + _digits(b) > MAX_DIGITS:
                raise _No
            if op in (ast.Div, ast.FloorDiv, ast.Mod) and b == 0:
                raise _No                             # a traceback on the real one
            try:
                v = _BIN[op](a, b)
            except (OverflowError, ValueError, ZeroDivisionError):
                raise _No from None
            if isinstance(v, float) and not math.isfinite(v) or \
                    isinstance(v, int) and _digits(v) > MAX_DIGITS:
                raise _No
            return v
        if op is ast.Add and ta is str and tb is str and len(a) + len(b) <= MAX_TEXT:
            return a + b
        if op is ast.Mult and {ta, tb} == {str, int}:
            s, k = (a, b) if ta is str else (b, a)
            if len(s) * max(k, 0) <= MAX_TEXT:
                return s * k
        raise _No
    raise _No


def output(code: str) -> str | None:
    """What `python3 -c code` prints, or None when the code is not only prints of
    constant expressions."""
    try:
        tree = ast.parse(code, mode="exec")
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    if not tree.body:
        return None
    out = []
    try:
        for st in tree.body:
            call = st.value if isinstance(st, ast.Expr) else None
            if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                    and call.func.id == "print" and not call.keywords
                    and not any(isinstance(a, ast.Starred) for a in call.args)):
                return None
            out.append(" ".join(str(_value(a)) for a in call.args) + "\n")
    except (_No, RecursionError):
        return None
    text = "".join(out)
    return text if len(text) <= MAX_TEXT else None
