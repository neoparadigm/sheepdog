"""Shell normalisation, path resolution, host extraction and rule matchers.

The shell normaliser is a conservative *approximation* of POSIX shell parsing. Anything it
cannot resolve (an unknown variable or substitution in command position) sets ``opaque`` so
rules can ask or deny instead of guessing. It never executes anything.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import ipaddress
import os
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from sheepdogai.core.events import ToolCallEvent
from sheepdogai.core.verdict import BudgetState
from sheepdogai.policy.schema import Match

MAX_CMD = 65536
MAX_DEPTH = 5
MAX_BRACE = 64
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "csh", "tcsh"}
STDIN_INTERPRETERS = {"python", "python3", "perl", "ruby", "node"}
DOWNLOADERS = {"curl", "wget", "fetch", "aria2c"}
NETWORK_PROGS = DOWNLOADERS | {
    "nc",
    "ncat",
    "netcat",
    "socat",
    "ssh",
    "scp",
    "sftp",
    "rsync",
    "ftp",
    "telnet",
    "http",
    "https",
}
KEYWORDS = {
    "if",
    "then",
    "else",
    "elif",
    "fi",
    "do",
    "done",
    "while",
    "until",
    "!",
    "time",
    "{",
    "}",
}
DROP_SEGMENT = {"for", "case", "esac", "in", "select", "function"}
WRAPPERS = {
    "env",
    "command",
    "builtin",
    "nohup",
    "time",
    "nice",
    "ionice",
    "timeout",
    "stdbuf",
    "exec",
    "xargs",
    "setsid",
}
WRAPPER_ARG_OPTS = {
    "nice": {"-n"},
    "ionice": {"-c", "-n"},
    "timeout": {"-s", "-k"},
    "xargs": {"-n", "-I", "-P", "-L", "-s", "-d", "-E"},
    "env": {"-u", "-C", "-S"},
    "stdbuf": set(),
}
READONLY = {
    "ls",
    "cat",
    "head",
    "tail",
    "less",
    "more",
    "pwd",
    "echo",
    "printf",
    "wc",
    "grep",
    "rg",
    "file",
    "stat",
    "du",
    "df",
    "which",
    "whoami",
    "id",
    "date",
    "uname",
    "diff",
    "sort",
    "uniq",
    "tree",
    "basename",
    "dirname",
    "realpath",
    "readlink",
    "true",
    "false",
    "test",
    "[",
    "cd",
    "type",
    "hostname",
    "nproc",
    "base64",
    "jq",
    "cut",
    "tr",
}
GIT_READONLY = {
    "status",
    "log",
    "diff",
    "show",
    "rev-parse",
    "ls-files",
    "blame",
    "describe",
    "shortlog",
    "remote",
    "config",
    "ls-remote",
    "grep",
    "reflog",
    "stash",
}
GIT_GLOBAL_WITH_ARG = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
DEFAULT_SCRATCH = ("/tmp", "/var/tmp", "/private/tmp", "/private/var/folders")
DEVICE_SCRATCH = ("/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/stdin")

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u00ad"))
_CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "ԁ": "d",
        "һ": "h",
        "ո": "n",
        "ս": "u",
        "ɡ": "g",
        "ɑ": "a",
        "ο": "o",
        "ν": "v",
        "ρ": "p",
        "τ": "t",
        "ι": "i",
        "κ": "k",
        "α": "a",
        "ε": "e",
        "А": "A",
        "В": "B",
        "Е": "E",
        "К": "K",
        "М": "M",
        "Н": "H",
        "О": "O",
        "Р": "P",
        "С": "C",
        "Т": "T",
        "Х": "X",
    }
)
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_URL = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]{1,12}://[^\s'\"<>`)\]}]{1,2048}")
_SECRET_ENV = re.compile(r"(?i)(key|token|secret|passw|credential|auth)")
_HOSTISH = re.compile(
    r"^(?:[\w.-]+@)?([A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3}|localhost)(?::\d+)?(?:[:/].*)?$"
)


def sanitize_unicode(s: str) -> tuple[str, list[str]]:
    """NFKC-normalise, drop zero-width characters, map common look-alike letters to ASCII."""
    notes: list[str] = []
    out = unicodedata.normalize("NFKC", s).translate(_ZERO_WIDTH)
    if out != s:
        notes.append("unicode_normalised")
    mapped = out.translate(_CONFUSABLES)
    if mapped != out:
        notes.append("homoglyphs_mapped")
    return mapped, notes


@dataclass
class Segment:
    """One simple command after normalisation."""

    argv: list[str]
    cmd: list[str]
    piped_from_prev: bool = False
    redirects: list[tuple[str, str]] = field(default_factory=list)
    privileged: bool = False

    @property
    def flat(self) -> str:
        """Space-joined normalised command (wrapper-stripped, argv0 basename)."""
        return " ".join(self.cmd)


@dataclass
class Parsed:
    """Result of normalising a shell command line."""

    segments: list[Segment] = field(default_factory=list)
    opaque: bool = False
    unresolved_vars: set[str] = field(default_factory=set)
    pipe_to_shell: bool = False
    notes: list[str] = field(default_factory=list)


def _ansi_c(s: str) -> str:
    out: list[str] = []
    i = 0
    simple = {
        "n": "\n",
        "t": "\t",
        "r": "\r",
        "a": "\a",
        "b": "\b",
        "e": "\x1b",
        "E": "\x1b",
        "f": "\f",
        "v": "\v",
        "\\": "\\",
        "'": "'",
        '"': '"',
        "?": "?",
    }
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n in simple:
                out.append(simple[n])
                i += 2
            elif n == "x":
                m = re.match(r"[0-9a-fA-F]{1,2}", s[i + 2 :])
                if m:
                    out.append(chr(int(m.group(), 16)))
                    i += 2 + len(m.group())
                else:
                    out.append("\\x")
                    i += 2
            elif n in "01234567":
                m = re.match(r"[0-7]{1,3}", s[i + 1 :])
                assert m
                out.append(chr(int(m.group(), 8) & 0xFF))
                i += 1 + len(m.group())
            elif n in "uU":
                m = re.match(r"[0-9a-fA-F]{1,8}", s[i + 2 :])
                if m:
                    try:
                        out.append(chr(int(m.group(), 16)))
                    except (ValueError, OverflowError):
                        out.append("?")
                    i += 2 + len(m.group())
                else:
                    out.append("\\" + n)
                    i += 2
            else:
                out.append("\\" + n)
                i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _match_paren(s: str, i: int) -> int:
    """Index of the ')' matching the '(' just before ``i`` (i is the first inner char)."""
    depth, quote = 1, ""
    while i < len(s):
        c = s[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 1
            elif c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c == "\\":
            i += 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(s)


def _brace_expand(word: list[tuple[str, bool]]) -> list[str]:
    """Expand one unquoted ``{a,b}`` group (iteratively, bounded)."""
    results = [word]
    for _ in range(4):
        nxt: list[list[tuple[str, bool]]] = []
        changed = False
        for w in results:
            start = next((i for i, (c, q) in enumerate(w) if c == "{" and not q), -1)
            if start < 0:
                nxt.append(w)
                continue
            depth, end, commas = 0, -1, []
            for j in range(start, len(w)):
                c, q = w[j]
                if q:
                    continue
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        end = j
                        break
                elif c == "," and depth == 1:
                    commas.append(j)
            if end < 0 or not commas:
                nxt.append(w)
                continue
            bounds = [start, *commas, end]
            for a, b in zip(bounds, bounds[1:], strict=False):
                nxt.append(w[:start] + w[a + 1 : b] + w[end + 1 :])
            changed = True
            if len(nxt) > MAX_BRACE:
                return ["".join(c for c, _ in w) for w in results][:MAX_BRACE]
        results = nxt
        if not changed:
            break
    return ["".join(c for c, _ in w) for w in results][:MAX_BRACE]


class _Parser:
    def __init__(self, env: dict[str, str], depth: int) -> None:
        self.env = dict(env)
        self.depth = depth
        self.out = Parsed()
        self.words: list[str] = []
        self.redirects: list[tuple[str, str]] = []
        self.pending_redirect: str | None = None
        self.piped = False
        self.sub_notes: list[str] = []

    # -- segment lifecycle -------------------------------------------------
    def _add_word(self, w: str) -> None:
        if self.pending_redirect is not None:
            self.redirects.append((self.pending_redirect, w))
            self.pending_redirect = None
        else:
            self.words.append(w)

    def _flush(self, op: str) -> None:
        words = self.words
        self.words = []
        redirects, self.redirects = self.redirects, []
        self.pending_redirect = None
        piped, self.piped = self.piped, op in {"|", "|&"}
        if not words and not redirects:
            return
        while words and words[0] in KEYWORDS:
            words = words[1:]
        if words and words[0] in DROP_SEGMENT:
            return
        # leading assignments
        i = 0
        while i < len(words) and _ASSIGN.match(words[i]):
            k, _, v = words[i].partition("=")
            self.env[k] = v
            i += 1
        argv = words[i:]
        if not argv:
            return
        self._finish_segment(argv, redirects, piped)

    def _finish_segment(
        self, argv: list[str], redirects: list[tuple[str, str]], piped: bool
    ) -> None:
        cmd, privileged = unwrap(argv)
        seg = Segment(
            argv=argv, cmd=cmd, piped_from_prev=piped, redirects=redirects, privileged=privileged
        )
        self.out.segments.append(seg)
        if not cmd:
            return
        head = cmd[0]
        if head in {"sudo", "doas"} and len(cmd) > 1:
            sudo_inner = _strip_sudo(cmd)
            if sudo_inner:
                self._finish_segment(sudo_inner, [], piped)
        if head.startswith("$") or head.startswith("\x00"):
            self.out.opaque = True
        # recurse into shells, eval, find -exec
        if head in SHELLS:
            payload = _dash_c_payload(cmd)
            if payload is not None:
                self._recurse(payload, downloads_flag=True)
            elif piped or len(cmd) == 1:
                self.out.pipe_to_shell = self.out.pipe_to_shell or piped
            if any(a.startswith("<(") for a in cmd[1:]):
                self.out.pipe_to_shell = True
        elif head in STDIN_INTERPRETERS and piped and len(cmd) == 1:
            self.out.pipe_to_shell = True
        elif head == "eval":
            self._recurse(" ".join(cmd[1:]), downloads_flag=True)
        elif head in {".", "source"} and len(cmd) > 1 and cmd[1] == "/dev/stdin":
            self.out.pipe_to_shell = True
        elif head == "find" and "-exec" in cmd:
            j = cmd.index("-exec") + 1
            inner: list[str] = []
            while j < len(cmd) and cmd[j] not in {";", "+", "\\;"}:
                inner.append(cmd[j])
                j += 1
            if inner:
                self._finish_segment(inner, [], False)
        elif (
            head == "base64"
            and piped
            and any(a in {"-d", "-D", "--decode", "-di"} for a in cmd[1:])
        ):
            prev = self.out.segments[-2] if len(self.out.segments) >= 2 else None
            if prev and prev.cmd and prev.cmd[0] in {"echo", "printf"}:
                self._recurse_b64(" ".join(prev.cmd[1:]))
        if (piped and head in SHELLS | STDIN_INTERPRETERS | {"eval"}) and len(cmd) == 1:
            self.out.pipe_to_shell = True

    def _recurse(self, text: str, downloads_flag: bool = False) -> None:
        if self.depth >= MAX_DEPTH:
            self.out.opaque = True
            self.out.notes.append("max_depth")
            return
        sub = parse_shell(text, self.env, self.depth + 1)
        self._merge(sub)
        if downloads_flag and ("$(" in text or "`" in text):
            if any(s.cmd and s.cmd[0] in DOWNLOADERS for s in sub.segments):
                self.out.pipe_to_shell = True

    def _recurse_b64(self, text: str) -> None:
        raw = re.sub(r"[\s'\"]", "", text)
        try:
            dec = base64.b64decode(raw + "=" * (-len(raw) % 4), validate=False).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return
        if dec and dec.isprintable() or "\n" in dec:
            self.out.notes.append("decoded_base64")
            self._recurse(dec)

    def _merge(self, sub: Parsed) -> None:
        self.out.segments.extend(sub.segments)
        self.out.opaque |= sub.opaque
        self.out.unresolved_vars |= sub.unresolved_vars
        self.out.pipe_to_shell |= sub.pipe_to_shell
        self.out.notes.extend(sub.notes)

    # -- scanning ----------------------------------------------------------
    def run(self, s: str) -> Parsed:  # noqa: C901
        """Scan ``s`` and return the parsed result."""
        i, n = 0, len(s)
        word: list[tuple[str, bool]] = []
        in_word = False
        heredocs: list[tuple[str, bool]] = []

        def end_word() -> None:
            nonlocal word, in_word
            if in_word:
                for w in _brace_expand(word):
                    self._add_word(w)
            word, in_word = [], False

        while i < n:
            c = s[i]
            if c in " \t":
                end_word()
                i += 1
            elif c == "\n":
                end_word()
                self._flush(";")
                i += 1
                for delim, strip in heredocs:
                    i = self._consume_heredoc(s, i, delim, strip)
                heredocs = []
            elif c == "\\":
                if i + 1 < n and s[i + 1] == "\n":
                    i += 2
                elif i + 1 < n:
                    word.append((s[i + 1], True))
                    in_word = True
                    i += 2
                else:
                    i += 1
            elif c == "'":
                j = s.find("'", i + 1)
                j = n if j < 0 else j
                word.extend((ch, True) for ch in s[i + 1 : j])
                in_word = True
                i = j + 1
            elif c == '"':
                i, text = self._dquote(s, i + 1)
                word.extend((ch, True) for ch in text)
                in_word = True
            elif c == "$" and s.startswith("$'", i):
                j = i + 2
                while j < n and not (s[j] == "'" and s[j - 1] != "\\"):
                    j += 1
                word.extend((ch, True) for ch in _ansi_c(s[i + 2 : j]))
                in_word = True
                i = j + 1
            elif c == "$" and s.startswith("$(", i) and not s.startswith("$((", i):
                j = _match_paren(s, i + 2)
                inner = s[i + 2 : j]
                self._subst(inner, as_command=not in_word and not self.words)
                word.extend((ch, True) for ch in "$(" + inner + ")")
                in_word = True
                i = j + 1
            elif c == "$" and s.startswith("$((", i):
                j = _match_paren(s, i + 2)
                word.extend((ch, True) for ch in s[i : j + 1])
                in_word = True
                i = j + 1
            elif c == "`":
                j = s.find("`", i + 1)
                j = n if j < 0 else j
                inner = s[i + 1 : j]
                self._subst(inner, as_command=not in_word and not self.words)
                word.extend((ch, True) for ch in "`" + inner + "`")
                in_word = True
                i = j + 1
            elif c == "$":
                i, text, brk = self._expand_var(s, i)
                if brk:
                    end_word()
                    if text:
                        word.extend((ch, True) for ch in text)
                        in_word = True
                        end_word()
                else:
                    word.extend((ch, True) for ch in text)
                    in_word = True
            elif c == "#" and not in_word:
                while i < n and s[i] != "\n":
                    i += 1
            elif c in "<>" and s.startswith(("<(", ">("), i):
                j = _match_paren(s, i + 2)
                inner = s[i + 2 : j]
                self._subst(inner, as_command=False)
                word.extend((ch, True) for ch in s[i : j + 1])
                in_word = True
                i = j + 1
            elif c in "<>":
                fd_prefix = in_word and all(ch.isdigit() for ch, _ in word)
                amp_prefix = c == ">" and in_word and bool(word) and word[-1][0] == "&"
                if fd_prefix or amp_prefix:
                    word, in_word = [], False
                end_word()
                m = re.match(r"(<<<|<<-?|>>|>\||&>>|&>|>&|<&|<|>)", s[i:])
                assert m
                op = m.group(1)
                i += len(op)
                if op in {"<<", "<<-"}:
                    # delimiter follows
                    k = i
                    while k < n and s[k] in " \t":
                        k += 1
                    m2 = re.match(r"""(['"]?)([A-Za-z0-9_.-]+)\1""", s[k:])
                    if m2:
                        heredocs.append((m2.group(2), op == "<<-"))
                        i = k + len(m2.group())
                else:
                    self.pending_redirect = op
            elif c in ";&|()":
                end_word()
                m = re.match(r"(;;|;&|&&|\|\||\|&|;|&|\||\(|\))", s[i:])
                assert m
                op = m.group(1)
                i += len(op)
                if op in {"(", ")"}:
                    self._flush(";")
                else:
                    self._flush(op)
            else:
                word.append((c, False))
                in_word = True
                i += 1
        end_word()
        self._flush(";")
        return self.out

    def _consume_heredoc(self, s: str, i: int, delim: str, strip: bool) -> int:
        body: list[str] = []
        n = len(s)
        while i < n:
            j = s.find("\n", i)
            line = s[i:] if j < 0 else s[i:j]
            i = n if j < 0 else j + 1
            if (line.lstrip("\t") if strip else line) == delim:
                break
            body.append(line)
        if self.out.segments:
            last = self.out.segments[-1]
            if last.cmd and last.cmd[0] in SHELLS:
                self._recurse("\n".join(body))
        return i

    def _subst(self, inner: str, as_command: bool) -> None:
        if as_command:
            self.out.opaque = True
        if self.depth >= MAX_DEPTH:
            self.out.opaque = True
            return
        self._merge(parse_shell(inner, self.env, self.depth + 1))

    def _dquote(self, s: str, i: int) -> tuple[int, str]:
        out: list[str] = []
        n = len(s)
        while i < n and s[i] != '"':
            c = s[i]
            if c == "\\" and i + 1 < n and s[i + 1] in '"\\$`\n':
                if s[i + 1] != "\n":
                    out.append(s[i + 1])
                i += 2
            elif c == "$" and s.startswith("$(", i):
                j = _match_paren(s, i + 2)
                inner = s[i + 2 : j]
                self._subst(inner, as_command=False)
                out.append("$(" + inner + ")")
                i = j + 1
            elif c == "`":
                j = s.find("`", i + 1)
                j = n if j < 0 else j
                self._subst(s[i + 1 : j], as_command=False)
                out.append(s[i : j + 1])
                i = j + 1
            elif c == "$":
                i, text, _ = self._expand_var(s, i, in_quotes=True)
                out.append(text)
            else:
                out.append(c)
                i += 1
        return i + 1, "".join(out)

    def _expand_var(self, s: str, i: int, in_quotes: bool = False) -> tuple[int, str, bool]:
        """Return (next index, replacement text, word_break). IFS expands to a word break."""
        if s.startswith("${", i):
            j = s.find("}", i + 2)
            j = len(s) if j < 0 else j
            inner = s[i + 2 : j]
            m = _NAME.match(inner)
            name = m.group() if m else inner
            rest = inner[len(name) :] if m else ""
            nxt = j + 1
        else:
            m = _NAME.match(s, i + 1)
            if not m:
                if i + 1 < len(s) and s[i + 1] in "123456789@*":
                    # positional parameters are empty in a fresh non-interactive shell
                    return i + 2, "", False
                if i + 1 < len(s) and s[i + 1] in "?!$#0-":
                    self.out.unresolved_vars.add(s[i + 1])
                    return i + 2, s[i : i + 2], False
                return i + 1, "$", False
            name, rest, nxt = m.group(), "", m.end()
        if name == "IFS":
            return nxt, "", not in_quotes
        val = self.env.get(name)
        if val is None and rest.startswith(":-"):
            val = rest[2:]
        if val is None:
            self.out.unresolved_vars.add(name)
            return nxt, "$" + name, False
        if rest and not rest.startswith(":-"):
            self.out.unresolved_vars.add(name)
            return nxt, "$" + name, False
        return nxt, val, False


def _strip_sudo(cmd: list[str]) -> list[str]:
    arg_opts = {"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t"}
    j = 1
    while j < len(cmd) and cmd[j].startswith("-"):
        j += 2 if cmd[j] in arg_opts else 1
    return cmd[j:]


def _dash_c_payload(cmd: list[str]) -> str | None:
    for k, a in enumerate(cmd[1:], start=1):
        if a == "--":
            return None
        if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
            return cmd[k + 1] if k + 1 < len(cmd) else None
        if not a.startswith("-"):
            return None
    return None


def unwrap(argv: list[str]) -> tuple[list[str], bool]:
    """Strip wrappers (env, nohup, xargs...), normalise argv0 and canonicalise git and rm."""
    a = list(argv)
    privileged = False
    for _ in range(8):
        if not a:
            break
        head = _base(a[0])
        a[0] = head
        if head in WRAPPERS:
            opts = WRAPPER_ARG_OPTS.get(head, set())
            j = 1
            while j < len(a):
                if a[j] in opts:
                    j += 2
                elif (
                    a[j].startswith("-")
                    or _ASSIGN.match(a[j])
                    or (head == "timeout" and re.fullmatch(r"\d+[smhd]?", a[j]))
                ):
                    j += 1
                else:
                    break
            a = a[j:]
            continue
        break
    if a:
        a[0] = _base(a[0])
        if a[0] == "sudo":
            privileged = True
        if a[0] == "git":
            a = _canon_git(a)
        elif a[0] == "rm":
            a = _canon_rm(a)
    return a, privileged


def _base(w: str) -> str:
    return w if w.startswith(("$", "`", "\x00")) else os.path.basename(w.lstrip("\\"))


def _canon_git(a: list[str]) -> list[str]:
    j = 1
    while j < len(a) and a[j].startswith("-"):
        j += 2 if a[j] in GIT_GLOBAL_WITH_ARG else 1
    return ["git", *a[j:]]


def _canon_rm(a: list[str]) -> list[str]:
    flags: set[str] = set()
    rest: list[str] = []
    end = False
    for t in a[1:]:
        if not end and t == "--":
            end = True
        elif not end and t.startswith("--"):
            long = {"--recursive": "r", "--force": "f"}.get(t)
            if long:
                flags.add(long)
        elif not end and t.startswith("-") and len(t) > 1:
            flags |= set(t[1:].replace("R", "r"))
        else:
            rest.append(t)
    out = ["rm"]
    if "r" in flags:
        out.append("-r")
    if "f" in flags:
        out.append("-f")
    return out + rest


def parse_shell(cmd: str, env: dict[str, str] | None = None, depth: int = 0) -> Parsed:
    """Normalise a shell command line into segments. Never raises."""
    try:
        text, notes = sanitize_unicode(cmd[:MAX_CMD])
        parsed = _Parser(env or {}, depth).run(text)
        parsed.notes.extend(notes)
        if len(cmd) > MAX_CMD:
            parsed.opaque = True
            parsed.notes.append("command_truncated")
        return parsed
    except Exception as e:  # fail closed: unknown structure => opaque
        return Parsed(opaque=True, notes=[f"parse_error:{type(e).__name__}"])


# --------------------------------------------------------------------------- paths


def resolve_path(p: str, cwd: str | None, home: str) -> str | None:
    """Resolve ``p`` with realpath so symlinks and '..' cannot escape. None if invalid."""
    if "\x00" in p:
        return None
    if p == "~" or p.startswith("~/"):
        p = home + p[1:]
    base = cwd or os.getcwd()
    try:
        return os.path.realpath(os.path.join(base, p))
    except (OSError, ValueError):
        return None


def is_inside(path: str, root: str) -> bool:
    """True when ``path`` equals or is below ``root`` (both already resolved)."""
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def is_scratch(path: str, scratch: tuple[str, ...] = DEFAULT_SCRATCH) -> bool:
    """Scratch locations that do not count as 'outside the project'."""
    return any(is_inside(path, s) for s in (*scratch, *DEVICE_SCRATCH))


def _glob_to_regex(g: str) -> re.Pattern[str]:
    out, i = [], 0
    while i < len(g):
        c = g[i]
        if c == "*":
            if g.startswith("**/", i):
                out.append("(?:.*/)?")
                i += 3
                continue
            if g.startswith("**", i):
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$", re.IGNORECASE)


def compile_path_glob(g: str, home: str, project: str) -> re.Pattern[str]:
    """Compile a path glob. ``~`` and ``{project}`` are expanded; a pattern with no '/'
    matches the basename at any depth; a relative pattern with '/' is project-relative."""
    g = g.replace("{project}", project)
    if g == "~" or g.startswith("~/"):
        g = home + g[1:]
    if "/" not in g:
        g = "**/" + g
    elif not g.startswith("/") and not g.startswith("**"):
        g = project.rstrip("/") + "/" + g
    return _glob_to_regex(g)


# --------------------------------------------------------------------------- facts


@dataclass
class Facts:
    """Everything the matchers need, derived once per event."""

    event: ToolCallEvent
    project: str
    home: str
    scratch: tuple[str, ...] = DEFAULT_SCRATCH
    parsed: Parsed | None = None
    paths: list[str] = field(default_factory=list)
    unresolvable_path: bool = False
    hosts: list[str] = field(default_factory=list)
    mutates: bool = False
    network_use: bool = False
    secret_env: bool = False
    text: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def command_strings(self) -> list[str]:
        """Candidate strings for command matchers."""
        c = self.event.args.get("command")
        first = [sanitize_unicode(c)[0]] if isinstance(c, str) else []
        if not self.parsed:
            return first
        out: list[str] = list(first)
        for s in self.parsed.segments:
            out.append(s.flat)
            joined = " ".join(s.argv)
            if joined != s.flat:
                out.append(joined)
        return out


def _candidates(tok: str) -> list[str]:
    out = [tok]
    if tok.startswith("-"):
        if "=" in tok:
            out.append(tok.split("=", 1)[1])
        m = re.match(r"^-[A-Za-z]([/~].*)$", tok)
        if m:
            out.append(m.group(1))
        out = out[1:]
    for sep in ("=", "@", ":"):
        if sep in tok and "://" not in tok:
            out.append(tok.rsplit(sep, 1)[1])
    return [c for c in out if c and not _URL.match(c)]


def _git_mutates(cmd: list[str]) -> bool:
    if len(cmd) < 2:
        return False
    sub = cmd[1]
    if sub not in GIT_READONLY:
        return True
    if sub in {"branch", "tag"} and any(a in {"-d", "-D", "--delete"} for a in cmd[2:]):
        return True
    return (
        sub in {"config", "remote", "stash"}
        and len(cmd) > 2
        and cmd[2] not in {"-l", "--list", "get", "show", "list", "-v", "--get"}
    )


def _segment_mutates(seg: Segment) -> bool:
    if any(
        op not in {"<", "<<", "<<<", "<&"} and t not in DEVICE_SCRATCH for op, t in seg.redirects
    ):
        return True
    if not seg.cmd:
        return False
    head = seg.cmd[0]
    if head == "git":
        return _git_mutates(seg.cmd)
    if head == "find":
        return any(a in {"-delete", "-exec", "-execdir", "-fprint", "-fprintf"} for a in seg.cmd)
    if head == "sed":
        return any(a.startswith("-i") or a == "--in-place" for a in seg.cmd[1:])
    if head == "sort":
        return any(a == "-o" or a.startswith("--output") for a in seg.cmd[1:])
    return head not in READONLY


def hosts_from_text(parsed: Parsed | None, strings: list[str]) -> list[str]:
    """Extract lower-cased hostnames from URLs and arguments of network programs."""
    hosts: list[str] = []
    for s in strings:
        for m in _URL.finditer(s):
            h = _url_host(m.group())
            if h:
                hosts.append(h)
    if parsed:
        for seg in parsed.segments:
            if seg.cmd and seg.cmd[0] in NETWORK_PROGS:
                for t in seg.cmd[1:]:
                    if t.startswith("-") or "://" in t:
                        continue
                    hm = _HOSTISH.match(t)
                    if hm:
                        hosts.append(hm.group(1))
                if seg.cmd[0] in {"nc", "ncat", "netcat", "telnet", "socat"}:
                    pass
    return sorted({_norm_host(h) for h in hosts})


_AUTHORITY = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/?#]*)")


def _url_host(url: str) -> str | None:
    """Hostname of a URL without urllib: strip userinfo and port, handle [ipv6]."""
    m = _AUTHORITY.match(url)
    if not m:
        return None
    auth = m.group(1).rsplit("@", 1)[-1]
    if auth.startswith("["):
        end = auth.find("]")
        return auth[1:end] if end > 0 else None
    return auth.split(":", 1)[0] or None


def _norm_host(h: str) -> str:
    h = h.strip().rstrip(".").lower()
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    try:
        return h.encode("idna").decode("ascii")
    except UnicodeError:
        return h


def event_text(event: ToolCallEvent) -> str:
    """All string content of the event args, for injection/disable-harness scanning."""
    parts: list[str] = []

    def walk(o: Any) -> None:
        if isinstance(o, str):
            parts.append(o)
        elif isinstance(o, dict):
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(event.args)
    return "\n".join(parts)


_MCP_READ = re.compile(r"(?i)(^|[_\-.])(get|list|read|search|view|find|fetch|describe|show|query)")
_DEVICES = {"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "/dev/stdin"}
_PATH_KEYS = ("file_path", "path", "filePath", "notebook_path", "target_file", "directory", "dir")
_PATCH_FILE = re.compile(r"^\*\*\* (?:Update|Add|Delete) File: (.+)$|^\*\*\* Move to: (.+)$", re.M)


_AMOUNT_KEYS = ("amount", "amount_usd", "price", "total", "value", "cost", "sum")
_RCPT_KEYS = (
    "to",
    "cc",
    "bcc",
    "recipient",
    "recipients",
    "attendees",
    "invitees",
    "email",
    "address",
    "channel",
)


def _num(v: Any) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        m = re.fullmatch(r"\s*[$€£]?\s*([0-9][0-9,]*(?:\.[0-9]+)?)\s*(?:usd|eur|gbp)?\s*", v, re.I)
        if m:
            return float(m.group(1).replace(",", ""))
    return None


def _personal_facts(f: Facts, own: tuple[str, ...]) -> None:
    """Amount, external-recipient and bulk facts used by the personal pack."""
    args = f.event.args
    amounts = [x for k in _AMOUNT_KEYS if (x := _num(args.get(k))) is not None]
    if amounts:
        f.extra["amount"] = max(amounts)
    rcpts: list[str] = []
    for k in _RCPT_KEYS:
        v = args.get(k)
        if isinstance(v, str):
            rcpts.extend(x.strip() for x in re.split(r"[,;]", v) if x.strip())
        elif isinstance(v, list):
            rcpts.extend(
                x if isinstance(x, str) else str(x.get("email", "")) if isinstance(x, dict) else ""
                for x in v
            )
    mine = {o.lower() for o in own}
    f.extra["recipient_external"] = (not rcpts) or any(r.lower() not in mine for r in rcpts)
    bulk = False
    for k, v in args.items():
        if isinstance(v, list) and len(v) >= 5:
            bulk = True
        if k in {"recursive", "all", "force_all"} and v is True:
            bulk = True
        if (
            isinstance(v, str)
            and k in {"path", "file_path", "pattern", "glob", "paths"}
            and re.search(r"[*?]", v)
        ):
            bulk = True
    if f.parsed:
        for seg in f.parsed.segments:
            if seg.cmd and seg.cmd[0] in {"rm", "find", "trash", "shred"}:
                if (
                    "-r" in seg.cmd
                    or "-delete" in seg.cmd
                    or any(re.search(r"[*?]", t) for t in seg.cmd[1:])
                ):
                    bulk = True
    f.extra["bulk"] = bulk


def compute_facts(
    event: ToolCallEvent,
    project: str,
    home: str,
    scratch: tuple[str, ...] = DEFAULT_SCRATCH,
    own_addresses: tuple[str, ...] = (),
) -> Facts:
    """Derive paths, hosts and flags for one event. Never raises."""
    f = Facts(event=event, project=project, home=home, scratch=scratch)
    try:
        raw: list[str] = []
        args = event.args
        for k in _PATH_KEYS:
            v = args.get(k)
            if isinstance(v, str):
                raw.append(v)
        for k in ("paths", "files"):
            v = args.get(k)
            if isinstance(v, list):
                raw.extend(x for x in v if isinstance(x, str))
        patch = args.get("patch") or args.get("input")
        if isinstance(patch, str):
            for m in _PATCH_FILE.finditer(patch):
                raw.append(m.group(1) or m.group(2))
        if event.tool.kind == "file_write" or (
            event.tool.kind in {"mcp", "other"} and not _MCP_READ.search(event.tool.name)
        ):
            f.mutates = True
        cmd = args.get("command")
        strings: list[str] = []
        if isinstance(cmd, str) and event.tool.kind in {"shell", "other", "mcp"}:
            f.parsed = parse_shell(cmd, {"HOME": home, "PWD": event.cwd or ""})
            strings.append(cmd)
            for seg in f.parsed.segments:
                for t in seg.cmd[1:]:
                    raw.extend(_candidates(t))
                for _, t in seg.redirects:
                    raw.append(t)
                if _segment_mutates(seg):
                    f.mutates = True
                if seg.cmd and seg.cmd[0] in NETWORK_PROGS:
                    f.network_use = True
            f.network_use |= f.parsed.pipe_to_shell and any(
                s.cmd and s.cmd[0] in DOWNLOADERS for s in f.parsed.segments
            )
            f.secret_env = any(_SECRET_ENV.search(v) for v in f.parsed.unresolved_vars)
            for s in f.parsed.segments:
                for t in s.cmd:
                    vm = re.fullmatch(r"\$\{?([A-Za-z_]\w*)\}?", t)
                    if vm and _SECRET_ENV.search(vm.group(1)):
                        f.secret_env = True
        url = args.get("url")
        if isinstance(url, str):
            strings.append(url)
            f.network_use = True
        if event.tool.kind == "network":
            f.network_use = True
        f.hosts = hosts_from_text(f.parsed, strings)
        if f.hosts:
            f.network_use = True
        for p in raw:
            rp = resolve_path(p, event.cwd, home)
            if rp is None:
                f.unresolvable_path = True
            elif rp not in _DEVICES:
                f.paths.append(rp)
        f.text = event_text(event)
        _personal_facts(f, own_addresses)
    except Exception as e:
        f.parsed = Parsed(opaque=True, notes=[f"facts_error:{type(e).__name__}"])
        f.extra["facts_error"] = type(e).__name__
    return f


# --------------------------------------------------------------------------- redos


def check_regex_safe(pattern: str) -> str | None:
    """Return an error string if ``pattern`` is invalid or looks vulnerable to ReDoS."""
    if len(pattern) > 400:
        return "regex longer than 400 characters"
    try:
        re.compile(pattern)
        import re._parser as sp  # type: ignore[import-not-found,unused-ignore]
    except re.error as e:
        return f"invalid regex: {e}"

    def unbounded(item: Any) -> bool:
        op, av = item
        return (
            str(op) in {"MAX_REPEAT", "MIN_REPEAT"}
            and av[1] > 50
            or str(op) == "POSSESSIVE_REPEAT"
            and av[1] > 50
        )

    def has_branch(tree: Any) -> bool:
        for op, av in tree:
            if str(op) == "BRANCH":
                return True
            if str(op) == "SUBPATTERN" and has_branch(av[3]):
                return True
        return False

    def walk(tree: Any, inside_rep: bool) -> str | None:
        for op, av in tree:
            name = str(op)
            if name in {"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"}:
                big = av[1] > 50 or av[1] == sp.MAXREPEAT
                if big and inside_rep:
                    return "nested unbounded repetition"
                sub = av[2]
                if big and has_branch(sub):
                    return "unbounded repetition over alternation"
                r = walk(sub, inside_rep or big)
                if r:
                    return r
            elif name == "SUBPATTERN":
                r = walk(av[3], inside_rep)
                if r:
                    return r
            elif name == "BRANCH":
                for br in av[1]:
                    r = walk(br, inside_rep)
                    if r:
                        return r
            elif name in {"ASSERT", "ASSERT_NOT"}:
                r = walk(av[1], False)
                if r:
                    return r
        return None

    return walk(sp.parse(pattern), False)


# --------------------------------------------------------------------------- matching


def _aslist(v: str | list[str] | None) -> list[str]:
    return [] if v is None else [v] if isinstance(v, str) else list(v)


class CompiledMatch:
    """A rule's match compiled once; call ``matches(facts, budget)``."""

    def __init__(
        self,
        m: Match,
        project: str,
        home: str,
        *,
        settings_cap: float = 50.0,
        delete_allow: list[str] | None = None,
    ) -> None:
        self.m = m
        self.tools = [t.lower() for t in _aslist(m.tool)]
        self.delete_allow = [compile_path_glob(g, home, project) for g in (delete_allow or [])]
        self.kinds = _aslist(m.kind)
        self.cmd_globs: list[str] = []
        self.cmd_res: list[re.Pattern[str]] = []
        for c in _aslist(m.command):
            if c.startswith("re:"):
                self.cmd_res.append(re.compile(c[3:]))
            else:
                self.cmd_globs.append(" ".join(c.split()))
        self.path_res = [compile_path_glob(g, home, project) for g in _aslist(m.path)]
        self.domains = [d.lower() for d in _aslist(m.domain)]
        self.domain_not = [d.lower() for d in _aslist(m.domain_not)]
        self.cap = settings_cap

    @staticmethod
    def _dom(host: str, pat: str) -> bool:
        if pat.startswith("*."):
            return host.endswith(pat[1:]) and host != pat[2:] or host == pat[2:]
        return host == pat

    def matches(self, f: Facts, b: BudgetState | None = None) -> bool:  # noqa: C901
        """Return True when every matcher in the rule holds for these facts."""
        m, ev = self.m, f.event
        if self.tools:
            tn = ev.tool.name.lower()
            if not any(tn == t or fnmatch.fnmatchcase(tn, t) for t in self.tools):
                return False
        if self.kinds and ev.tool.kind not in self.kinds:
            return False
        if self.cmd_globs or self.cmd_res:
            strings = f.command_strings
            ok = any(fnmatch.fnmatchcase(s, g) for s in strings for g in self.cmd_globs) or any(
                r.search(s[:MAX_CMD]) for s in strings for r in self.cmd_res
            )
            if not ok:
                return False
        if self.path_res and not any(r.match(p) for p in f.paths for r in self.path_res):
            return False
        if self.domains and not any(self._dom(h, d) for h in f.hosts for d in self.domains):
            return False
        if self.domain_not and not any(
            not any(self._dom(h, d) for d in self.domain_not) for h in f.hosts
        ):
            return False
        if m.provenance is not None and m.provenance.untrusted_content_seen is not None:
            if ev.provenance.untrusted_content_seen != m.provenance.untrusted_content_seen:
                return False
        if m.budget is not None:
            if b is None:
                return False
            bm = m.budget
            if (
                (bm.steps_gt is not None and not b.steps > bm.steps_gt)
                or (bm.cost_gt is not None and not b.cost_usd > bm.cost_gt)
                or (bm.repeats_gt is not None and not b.repeats > bm.repeats_gt)
            ):
                return False
        if m.outside_project is not None:
            out = f.unresolvable_path or any(
                p == f.home or (not is_inside(p, f.project) and not is_scratch(p, f.scratch))
                for p in f.paths
            )
            if out != m.outside_project:
                return False
        if m.mutates is not None and f.mutates != m.mutates:
            return False
        if m.network_use is not None and f.network_use != m.network_use:
            return False
        if (
            m.pipe_to_shell is not None
            and bool(f.parsed and f.parsed.pipe_to_shell) != m.pipe_to_shell
        ):
            return False
        if m.opaque is not None and bool(f.parsed and f.parsed.opaque) != m.opaque:
            return False
        if m.secret_env is not None and f.secret_env != m.secret_env:
            return False
        if m.amount_over_cap is not None:
            amt = f.extra.get("amount")
            over = isinstance(amt, (int, float)) and amt > self.cap
            if over != m.amount_over_cap:
                return False
        if m.outside_allowlist is not None:
            outside = (not f.paths) or any(
                not any(r.match(p) for r in self.delete_allow) for p in f.paths
            )
            if outside != m.outside_allowlist:
                return False
        if m.bulk is not None and bool(f.extra.get("bulk")) != m.bulk:
            return False
        if m.amount_gt is not None:
            amt = f.extra.get("amount")
            if not isinstance(amt, (int, float)) or not amt > m.amount_gt:
                return False
        if (
            m.recipient_external is not None
            and bool(f.extra.get("recipient_external")) != m.recipient_external
        ):
            return False
        return True
