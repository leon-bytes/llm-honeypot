"""Go's text/template, as much of it as `docker --format` needs.

`docker ps --format`, `docker images --format` and `docker inspect -f` take a Go
template. To answer them in code from the shared Docker state (and never hand a
shared-state question to the model), the shell has to evaluate such templates itself.
This is a small interpreter for the part of the language people type at a docker prompt:

  {{.Field.Sub}}  {{$var}}  {{"text"}}  numbers, true/false/nil, ( pipelines )
  {{if}} {{else if}} {{else}} {{end}}   {{range [$i, $v :=] X}} {{else}} {{end}}
  {{with X}} {{end}}   {{$x := X}}   a | b | c   {{- trim -}}   {{/* comments */}}
  and or not eq ne lt le gt ge len index print printf println
  and docker's own: json join split upper lower title truncate pad

Values are what JSON gives (dict, list, str, bool, None, numbers kept as written), or an
`Obj`: a named Go struct with a fixed set of fields, which is what `docker ps` and
`docker images` evaluate templates against. Errors carry Go's own wording, which docker
prints: `template: :1:2: executing "" at <.Nope>: map has no entry for key "Nope"`.

Checked against the real client, case by case (tools/docker_cli_oracle.py,
tests/test_dockercli.py). Not implemented: define/template/block, break/continue, and
character-exact error positions for errors other than a bad field or function.
"""
from __future__ import annotations
import json
import re


class TemplateError(Exception):
    """A parse or execution error; str() is Go's message, starting `template: :1:`."""

    def __init__(self, message: str, parsing: bool):
        super().__init__(message)
        self.parsing = parsing


class Num(str):
    """A JSON number, kept as written: Go prints 191635456, not 1.91635456e+08."""

    @property
    def value(self):
        return float(self) if re.search(r"[.eE]", self) else int(self)


class Obj:
    """A Go struct with methods, by name: `fields` maps a field to a value or to a
    function of the template's arguments."""

    def __init__(self, typename: str, fields: dict):
        self.typename, self.fields = typename, fields


def loads(text: str):
    """json.loads that keeps numbers as written and objects in document order."""
    return json.loads(text, parse_int=Num, parse_float=Num)


# ------------------------------------------------------------------ printing values

def go_json(v, escape_html: bool = False) -> str:
    """Compact JSON in document order. docker's `json` template function does not
    escape < > &; a context object marshals itself with Go's default, which does."""
    def conv(x):
        if isinstance(x, Num):
            return x.value
        if isinstance(x, dict):
            return {k: conv(val) for k, val in x.items()}
        if isinstance(x, list):
            return [conv(val) for val in x]
        return x
    if isinstance(v, Obj):
        fields = {k: conv(f() if callable(f) else f) for k, f in sorted(v.fields.items())
                  if not getattr(f, "takes_args", False)}
        out = json.dumps(fields, ensure_ascii=False, separators=(",", ":"))
        return out.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    out = json.dumps(conv(v), ensure_ascii=False, separators=(",", ":"))
    if escape_html:
        out = out.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return out


def sprint(v) -> str:
    """fmt.Sprint of a value: strings bare, [a b c], map[k:v] with sorted keys."""
    if v is None:
        return "<nil>"
    if hasattr(v, "go_string"):
        return v.go_string()
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (str, int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + " ".join(sprint(x) for x in v) + "]"
    if isinstance(v, dict):
        return "map[" + " ".join(f"{k}:{sprint(v[k])}" for k in sorted(v)) + "]"
    if isinstance(v, Obj):
        return "{" + v.typename + "}"
    return str(v)


def truth(v) -> bool:
    if isinstance(v, Num):
        return v.value != 0
    return bool(v)


def _number(v):
    if isinstance(v, Num):
        return v.value
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise TypeError
    return v


# ------------------------------------------------------------------ lexing an action

_TOKEN = re.compile(r'''\s*(?:
      (?P<str>"(?:[^"\\]|\\.)*")
    | (?P<raw>`[^`]*`)
    | (?P<num>[-+]?\d+(?:\.\d+)?)
    | (?P<assign>:=|=)
    | (?P<punct>[(),|])
    | (?P<var>\$[A-Za-z0-9_]*)
    | (?P<field>(?:\.[A-Za-z_][A-Za-z0-9_]*)+)
    | (?P<dot>\.)
    | (?P<word>[A-Za-z_][A-Za-z0-9_]*)
)''', re.X)


def _lex(text: str, base: int) -> list[tuple[str, str, int]]:
    """Tokens of one action as (kind, text, position in the whole template)."""
    out, i = [], 0
    while i < len(text):
        m = _TOKEN.match(text, i)
        if not m or m.end() == i:
            if not text[i:].strip():
                break
            bad = text[i:].lstrip()[0]
            raise TemplateError(f'template: :1: unexpected "{bad}" in command', True)
        kind = m.lastgroup
        out.append((kind, m.group(kind), base + m.start(kind)))
        i = m.end()
    return out


# ------------------------------------------------------------------ parsing

_KEYWORDS = {"if", "else", "end", "range", "with"}


class _Parser:
    def __init__(self, source: str, funcs: dict):
        self.funcs = funcs
        self.items = self._split(source)
        self.i = 0

    @staticmethod
    def _split(source: str):
        """[('text', str) | ('action', tokens, text of the action)]."""
        items, pos = [], 0
        while True:
            a = source.find("{{", pos)
            if a < 0:
                items.append(("text", source[pos:]))
                return items
            b = source.find("}}", a + 2)
            if b < 0:
                raise TemplateError("template: :1: unclosed action", True)
            text = source[pos:a]
            inner, start = source[a + 2:b], a + 2
            if inner.startswith("- "):
                text, inner, start = text.rstrip(), inner[2:], start + 2
            trim_after = inner.endswith(" -")
            if trim_after:
                inner = inner[:-2]
            items.append(("text", text))
            if not re.fullmatch(r"\s*/\*.*\*/\s*", inner, re.S):
                items.append(("action", inner, start))
            pos = b + 2
            if trim_after:
                rest = source[pos:]
                pos += len(rest) - len(rest.lstrip())

    def parse(self, until=()):
        """Nodes up to one of the keywords in `until`; returns (nodes, the keyword's
        tokens or None at the end of the template)."""
        nodes = []
        while self.i < len(self.items):
            item = self.items[self.i]
            self.i += 1
            if item[0] == "text":
                if item[1]:
                    nodes.append(("text", item[1]))
                continue
            toks = _lex(item[1], item[2])
            if not toks:
                raise TemplateError("template: :1: missing value for command", True)
            head = toks[0][1] if toks[0][0] == "word" else None
            if head in until:
                return nodes, toks
            if head in ("if", "with", "range"):
                nodes.append(self._block(head, toks[1:]))
            elif head in ("end", "else"):
                raise TemplateError(f"template: :1: unexpected {{{{{head}}}}}", True)
            else:
                nodes.append(("action", self._pipeline(toks)))
        if until:
            raise TemplateError("template: :1: unexpected EOF", True)
        return nodes, None

    def _block(self, kind: str, toks):
        variables = []
        if kind == "range":
            m = [t for t in toks if t[0] == "assign"]
            if m:
                cut = toks.index(m[0])
                variables = [t[1] for t in toks[:cut] if t[0] == "var"]
                toks = toks[cut + 1:]
        pipe = self._pipeline(toks)
        body, closer = self.parse(until=("else", "end"))
        other = []
        if closer[0][1] == "else":
            if len(closer) > 1 and closer[1][1] == "if":            # else if
                other = [self._block("if", closer[2:])]
                return (kind, pipe, variables, body, other)
            other, closer = self.parse(until=("end",))
        return (kind, pipe, variables, body, other)

    def _pipeline(self, toks):
        """('pipe', declared variable or None, [command, ...]); a command is a list of
        operands, the first of which may be a function."""
        declare = None
        if len(toks) >= 2 and toks[0][0] == "var" and toks[1][0] == "assign":
            declare, toks = toks[0][1], toks[2:]
        commands, current, depth, sub = [], [], 0, []
        i = 0
        while i < len(toks):
            kind, text, pos = toks[i]
            if kind == "punct" and text == "(":
                depth, j = 1, i + 1
                while j < len(toks) and depth:
                    depth += (toks[j][1] == "(") - (toks[j][1] == ")")
                    j += 1
                if depth:
                    raise TemplateError("template: :1: unclosed left paren", True)
                node = ("paren", self._pipeline(toks[i + 1:j - 1]))
                i = j
                if i < len(toks) and toks[i][0] == "field":          # (pipeline).Field
                    node = ("chain", node, toks[i][1], toks[i][2])
                    i += 1
                current.append(node)
                continue
            if kind == "punct" and text == "|":
                if not current:
                    raise TemplateError("template: :1: missing value for command", True)
                commands.append(current)
                current = []
            elif kind == "punct":
                raise TemplateError(f'template: :1: unexpected "{text}" in command', True)
            else:
                current.append(self._operand(kind, text, pos, toks, i))
                if kind == "var" and i + 1 < len(toks) and toks[i + 1][0] == "field" \
                        and toks[i + 1][2] == pos + len(text):
                    i += 1                                           # $v.Field: one operand
            i += 1
        if not current:
            raise TemplateError("template: :1: missing value for command", True)
        commands.append(current)
        return ("pipe", declare, commands)

    def _operand(self, kind, text, pos, toks, i):
        if kind == "str":
            return ("const", json.loads(text))
        if kind == "raw":
            return ("const", text[1:-1])
        if kind == "num":
            return ("const", Num(text))
        if kind == "dot":
            return ("dot",)
        if kind == "field":
            names = text[1:].split(".")
            # Go reports a chain at its second field, a single field at itself.
            at = pos + (1 + len(names[0]) if len(names) > 1 else 0)
            return ("field", names, text, at)
        if kind == "var":
            if i + 1 < len(toks) and toks[i + 1][0] == "field" and toks[i + 1][2] == pos + len(text):
                f = toks[i + 1]
                return ("varfield", text, f[1][1:].split("."), text + f[1], f[2])
            return ("var", text)
        if kind == "word":
            if text in ("true", "false"):
                return ("const", text == "true")
            if text == "nil":
                return ("const", None)
            if text not in self.funcs and text not in _KEYWORDS:
                raise TemplateError(f'template: :1: function "{text}" not defined', True)
            return ("func", text)
        raise TemplateError(f'template: :1: unexpected "{text}" in command', True)


# ------------------------------------------------------------------ executing

class Template:
    def __init__(self, source: str, extra_funcs: dict | None = None,
                 missing_key_is_error: bool = True):
        self.funcs = {**_FUNCS, **(extra_funcs or {})}
        self.strict = missing_key_is_error
        self.nodes, _ = _Parser(source, self.funcs).parse()

    def render(self, data) -> str:
        out = []
        self._run(self.nodes, data, {"$": data}, out)
        return "".join(out)

    def _run(self, nodes, dot, scope, out):
        for node in nodes:
            kind = node[0]
            if kind == "text":
                out.append(node[1])
            elif kind == "action":
                value = self._pipe(node[1], dot, scope)
                if node[1][1] is None:                   # a declaration prints nothing
                    out.append(self._show(value))
            elif kind in ("if", "with"):
                value = self._pipe(node[1], dot, scope)
                inner = dict(scope)
                if truth(value):
                    self._run(node[3], value if kind == "with" else dot, inner, out)
                else:
                    self._run(node[4], dot, inner, out)
            elif kind == "range":
                value = self._pipe(node[1], dot, scope)
                if isinstance(value, dict):
                    pairs = [(k, value[k]) for k in sorted(value)]
                elif isinstance(value, list):
                    pairs = [(Num(str(i)), x) for i, x in enumerate(value)]
                elif value is None:
                    pairs = []
                else:
                    raise TemplateError(f"template: :1: executing \"\": range can't iterate over "
                                        f"{sprint(value)}", False)
                if not pairs:
                    self._run(node[4], dot, dict(scope), out)
                for k, v in pairs:
                    inner = dict(scope)
                    names = node[2]
                    if len(names) == 1:
                        inner[names[0]] = v
                    elif len(names) == 2:
                        inner[names[0]], inner[names[1]] = k, v
                    self._run(node[3], v, inner, out)

    @staticmethod
    def _show(value) -> str:
        return "<no value>" if value is _MISSING else sprint(value)

    def _pipe(self, pipe, dot, scope):
        _, declare, commands = pipe
        value, have = None, False
        for command in commands:
            value = self._command(command, dot, scope, [value] if have else [])
            have = True
        if declare:
            scope[declare] = value
        return value

    def _command(self, command, dot, scope, piped):
        first = command[0]
        if first[0] == "func":
            args = [self._eval(a, dot, scope) for a in command[1:]] + piped
            return self._call(first[1], args)
        if first[0] == "field" and isinstance(dot, Obj) and len(first[1]) == 1 \
                and getattr(dot.fields.get(first[1][0]), "takes_args", False):
            args = [self._eval(a, dot, scope) for a in command[1:]] + piped
            return dot.fields[first[1][0]](*args)                   # a method with arguments
        if len(command) > 1 or piped:
            raise TemplateError(f"template: :1: executing \"\": can't give argument to "
                                f"non-function {self._text(first)}", False)
        return self._eval(first, dot, scope)

    @staticmethod
    def _text(node) -> str:
        return node[2] if node[0] == "field" else str(node[1])

    def _eval(self, node, dot, scope):
        kind = node[0]
        if kind == "const":
            return node[1]
        if kind == "dot":
            return dot
        if kind == "field":
            return self._fields(dot, node[1], node[2], node[3])
        if kind == "var":
            if node[1] not in scope:
                raise TemplateError(f"template: :1: undefined variable \"{node[1]}\"", True)
            return scope[node[1]]
        if kind == "varfield":
            if node[1] not in scope:
                raise TemplateError(f"template: :1: undefined variable \"{node[1]}\"", True)
            return self._fields(scope[node[1]], node[2], node[3], node[4])
        if kind == "paren":
            return self._pipe(node[1], dot, scope)
        if kind == "chain":
            return self._fields(self._eval(node[1], dot, scope), node[2][1:].split("."),
                                node[2], node[3])
        if kind == "func":
            return self._call(node[1], [])
        raise TemplateError("template: :1: unexpected node", True)

    def _fields(self, value, names, text, at):
        where = f'template: :1:{at}: executing "" at <{text}>'
        for name in names:
            if isinstance(value, Obj):
                if name not in value.fields:
                    raise TemplateError(f"{where}: can't evaluate field {name} in type "
                                        f"{value.typename}", False)
                f = value.fields[name]
                value = f() if callable(f) else f
            elif isinstance(value, dict):
                if name not in value and name in getattr(value, "also", {}):
                    value = value.also[name]         # a field the Go structure has
                    continue
                if name not in value:
                    if self.strict:
                        raise TemplateError(f'{where}: map has no entry for key "{name}"', False)
                    return _MISSING
                value = value[name]
            elif value is None or value is _MISSING:
                raise TemplateError(f"{where}: nil pointer evaluating interface {{}}.{name}", False)
            else:
                kind = ("string" if isinstance(value, str) and not isinstance(value, Num) else
                        "bool" if isinstance(value, bool) else
                        "[]interface {}" if isinstance(value, list) else "json.Number")
                raise TemplateError(f"{where}: can't evaluate field {name} in type {kind}", False)
        return value

    def _call(self, name, args):
        try:
            return self.funcs[name](*args)
        except TemplateError:
            raise
        except Exception as e:
            raise TemplateError(f'template: :1: executing "" at <{name}>: error calling {name}: {e}',
                                False)


_MISSING = object()


# ------------------------------------------------------------------ functions

def _printf(fmt, *args):
    """Go's fmt.Sprintf for the verbs people use: %s %v %d %q %x %t %f %%, with flags
    and widths."""
    args = list(args)

    def one(m):
        flags, width, prec, verb = m.group(1), m.group(2), m.group(3), m.group(4)
        if verb == "%":
            return "%"
        if not args:
            return f"%!{verb}(MISSING)"
        a = args.pop(0)
        if verb in "sv":
            text = sprint(a)
            if prec:
                text = text[:int(prec[1:])]
        elif verb == "q":
            text = json.dumps(sprint(a), ensure_ascii=False)
        elif verb == "d":
            try:
                n = int(_number(a))
            except (TypeError, ValueError):
                return f"%!d({_gotype(a)}={sprint(a)})"
            text = f"{n:+d}" if "+" in flags else str(n)
            if "0" in flags and width and "-" not in flags:
                return text.zfill(int(width))
        elif verb in "xX":
            text = format(int(_number(a)), verb) if not isinstance(a, str) or isinstance(a, Num) \
                else a.encode().hex()
        elif verb == "t":
            text = sprint(a)
        elif verb in "fFeg":
            text = format(float(_number(a)), f"{prec or '.6'}{verb}")
        else:
            return f"%!{verb}({_gotype(a)}={sprint(a)})"
        if width:
            text = text.ljust(int(width)) if "-" in flags else text.rjust(int(width))
        return text
    out = re.sub(r"%([-+0 #]*)(\d+)?(\.\d+)?([a-zA-Z%])", one, fmt)
    if args:
        out += "%!(EXTRA " + ", ".join(f"{_gotype(a)}={sprint(a)}" for a in args) + ")"
    return out


def _gotype(v) -> str:
    if isinstance(v, Num):
        return "json.Number"
    return {str: "string", bool: "bool", type(None): "<nil>"}.get(type(v), "interface {}")


def _compare(op):
    def f(a, *rest):
        if not rest:
            raise TemplateError(f'template: :1: executing "" at <{op}>: error calling {op}: '
                                f"missing argument for comparison", False)
        def norm(x):
            return x.value if isinstance(x, Num) else x
        a = norm(a)
        if op == "eq":
            return any(a == norm(b) for b in rest)
        b = norm(rest[0])
        return {"ne": a != b, "lt": a < b, "le": a <= b, "gt": a > b, "ge": a >= b}[op]
    return f


def _index(value, *keys):
    for k in keys:
        if isinstance(value, dict):
            value = value.get(k)
        elif isinstance(value, (list, str)):
            i = int(_number(k))
            if not 0 <= i < len(value):
                raise TemplateError(f'template: :1: executing "" at <index>: error calling index: '
                                    f"index out of range: {i}", False)
            value = value[i]
        else:
            raise TemplateError('template: :1: executing "" at <index>: error calling index: '
                                "index of untyped nil", False)
    return value


def _len(v):
    if isinstance(v, (str, list, dict)) and not isinstance(v, Num):
        return Num(str(len(v.encode()) if isinstance(v, str) else len(v)))
    raise ValueError(f"len of type {_gotype(v)}")


def _and(*args):
    for a in args:
        if not truth(a):
            return a
    return args[-1]


def _or(*args):
    for a in args:
        if truth(a):
            return a
    return args[-1]


def _truncate(s, n):
    n = int(_number(n))
    return s if len(s) <= n else s[:n]


def _pad(s, before, after):
    return s and " " * int(_number(before)) + s + " " * int(_number(after))


_FUNCS = {
    "and": _and, "or": _or, "not": lambda a: not truth(a),
    "eq": _compare("eq"), "ne": _compare("ne"), "lt": _compare("lt"), "le": _compare("le"),
    "gt": _compare("gt"), "ge": _compare("ge"),
    "len": _len, "index": _index,
    "print": lambda *a: "".join(sprint(x) for x in a),
    "println": lambda *a: " ".join(sprint(x) for x in a) + "\n",
    "printf": _printf,
    "json": go_json,
    "join": lambda items, sep: sep.join(sprint(x) for x in items),
    "split": lambda s, sep: s.split(sep),
    "upper": lambda s: s.upper(), "lower": lambda s: s.lower(),
    "title": lambda s: re.sub(r"(^|\s)(\S)", lambda m: m.group(1) + m.group(2).upper(), s),
    "truncate": _truncate, "pad": _pad,
}
