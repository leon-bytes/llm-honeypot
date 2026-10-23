"""The site's own values, kept out of everything that is published.

The honeypot's code is published in a repository; the addresses of this lab, the credentials the simulated machine serves and
the names of the machine it is developed on are not. They are all in ONE local file,
`site.local.json` at the project root, which git ignores. `site.example.json`, which is
committed, has the same keys with made-up values, each as long as the real one (so a
column width or a stream frame's length is the same with either), and the code and the
tests run on it.

Which file: $HONEYPOT_SITE if it is set, else `site.local.json` if it exists, else the
example. The choice is made once, at import, since some values are part of texts built
then (the model's instructions). The relay itself starts on the example only when told to
(`relay.py --example-site`), so a deploy that forgot the local file cannot serve made-up
values.

A data file or the config may hold `@@key@@` where a value belongs; `fill()` puts the
value in before the text is parsed (`load_json`), so what the code sees is the same text
as before the values were moved out. `tokens()` is the reverse, for the tools that write
such a file from live answers (a recorded fixture, the Docker seed). Standard library
only.
"""
import json
import os
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
LOCAL = ROOT / "site.local.json"
EXAMPLE = ROOT / "site.example.json"
_TOKEN = re.compile(r"@@([a-z0-9_]+)@@")


class SiteError(Exception):
    pass


def _choose() -> pathlib.Path:
    env = os.environ.get("HONEYPOT_SITE")
    if env:
        return pathlib.Path(env)
    return LOCAL if LOCAL.exists() else EXAMPLE


def _read(path: pathlib.Path) -> dict:
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    values = {k: v for k, v in raw.items() if not k.startswith("_")}
    for k, v in values.items():
        if not isinstance(v, str) or not v or '"' in v or "\\" in v or "@@" in v:
            raise SiteError(f"{path}: {k} must be a non-empty string without quotes, "
                            "backslashes or @@")
    return values


class Site:
    def __init__(self, path: pathlib.Path):
        self.path = pathlib.Path(path).resolve()
        self.values = _read(self.path)
        if self.path != EXAMPLE.resolve() and EXAMPLE.exists():
            want = set(_read(EXAMPLE))
            have = set(self.values)
            if want != have:
                raise SiteError(f"{self.path} and {EXAMPLE.name} differ in their keys: "
                                f"missing {sorted(want - have)}, extra {sorted(have - want)}")

    @property
    def is_example(self) -> bool:
        return self.path == EXAMPLE.resolve()

    def __getitem__(self, key: str) -> str:
        return self.values[key]

    def __getattr__(self, key: str) -> str:
        try:
            return self.__dict__["values"][key]
        except KeyError:
            raise AttributeError(key) from None

    def fill(self, text: str) -> str:
        """Every `@@key@@` replaced by its value; an unknown key is an error."""
        def one(m):
            if m.group(1) not in self.values:
                raise SiteError(f"unknown site value @@{m.group(1)}@@")
            return self.values[m.group(1)]
        return _TOKEN.sub(one, text)

    def tokens(self, text: str, keys=None) -> str:
        """The reverse of fill(): each value (longest first) replaced by its `@@key@@`,
        where it stands on its own (10.0.0.1 is not taken out of 10.0.0.12; in JSON text a
        value right after an escape such as \\n or \\t stands on its own too). `keys`
        limits it to some values (the ones a file is known to hold)."""
        for k in sorted(keys or self.values, key=lambda k: -len(self.values[k])):
            v = re.escape(self.values[k])
            text = re.sub(rf"(?:(?<=\\[nrt])|(?<![\w.])){v}(?![\w]|\.\d)", f"@@{k}@@", text)
        return text

    def load_json(self, path):
        """A JSON file with its `@@key@@` filled in, parsed."""
        return json.loads(self.fill(pathlib.Path(path).read_text(encoding="utf-8")))


SITE = Site(_choose())

