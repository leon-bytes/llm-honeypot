"""The team-only recordings some tests compare with (the reference machine's answers, the
corpus, the API recordings, its front door).

They are not in the shared repository: they hold the reference machine's credentials,
password hashes and real addresses. A test that needs one runs only when the recording is
at the project root AND the real site values are in use (site.local.json: the recordings
hold the real values, so they cannot match the example's); otherwise it is skipped, and
says which file it needs. On a fresh clone with site.example.json the rest of the suite
runs.

  load(name)    the parsed recording, or SkipTest
  path(name)    its path, or SkipTest
  lazy(make)    a stand-in for a module-level table built from recordings: built on first
                use, so only the tests that use it are skipped
"""
import json
import pathlib
import unittest

from honeypot.site import SITE

ROOT = pathlib.Path(__file__).resolve().parent.parent


def available(name: str) -> bool:
    return not SITE.is_example and (ROOT / name).exists()


def path(name: str) -> pathlib.Path:
    if not available(name):
        raise unittest.SkipTest(f"needs the team-only recording {name} and site.local.json")
    return ROOT / name


def load(name: str):
    with open(path(name), encoding="utf-8") as f:
        return json.load(f)


class lazy:
    """Behaves as the dict or list `make()` returns, which is built on first use."""

    def __init__(self, make):
        self._make, self._value = make, None

    def _get(self):
        if self._value is None:
            self._value = self._make()
        return self._value

    def __getitem__(self, k):
        return self._get()[k]

    def __iter__(self):
        return iter(self._get())

    def __len__(self):
        return len(self._get())

    def __contains__(self, k):
        return k in self._get()

    def __getattr__(self, name):          # .items(), .get(), .values(), ...
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self._get(), name)
