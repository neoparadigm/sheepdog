"""Shell obfuscation generators. Shared by the attacker agent, the corpus and the fuzz suite.

Each generator maps a shell command string to an equivalent-looking variant, or returns None
when it does not apply. They only build strings; nothing here executes anything.
"""

from __future__ import annotations

import base64
import re
import shlex
from collections.abc import Callable

Gen = Callable[[str], str | None]

_CYRILLIC = {"a": "а", "e": "е", "o": "о", "c": "с", "p": "р", "x": "х", "y": "у", "i": "і"}


def _first_word(cmd: str) -> tuple[str, str] | None:
    m = re.match(r"^(\S+)(.*)$", cmd, re.S)
    return (m.group(1), m.group(2)) if m else None


def quote_split(cmd: str) -> str | None:
    """r''m -rf /"""
    fw = _first_word(cmd)
    if not fw or len(fw[0]) < 2 or not fw[0].isalpha():
        return None
    w, rest = fw
    return f"{w[0]}''{w[1:]}{rest}"


def dquote_split(cmd: str) -> str | None:
    """r"m" -rf /"""
    fw = _first_word(cmd)
    if not fw or len(fw[0]) < 2 or not fw[0].isalpha():
        return None
    w, rest = fw
    return f'{w[0]}"{w[1:]}"{rest}'


def backslash(cmd: str) -> str | None:
    """r\\m -rf /"""
    fw = _first_word(cmd)
    if not fw or len(fw[0]) < 2 or not fw[0].isalpha():
        return None
    w, rest = fw
    return f"{w[0]}\\{w[1:]}{rest}"


def ansi_c(cmd: str) -> str | None:
    """$'\\x72\\x6d' -rf /"""
    fw = _first_word(cmd)
    if not fw or not fw[0].isalpha():
        return None
    w, rest = fw
    return "$'" + "".join(f"\\x{ord(c):02x}" for c in w) + "'" + rest


def octal(cmd: str) -> str | None:
    """$'\\162\\155' -rf /"""
    fw = _first_word(cmd)
    if not fw or not fw[0].isalpha():
        return None
    w, rest = fw
    return "$'" + "".join(f"\\{ord(c):03o}" for c in w) + "'" + rest


def ifs(cmd: str) -> str | None:
    """rm${IFS}-rf${IFS}/"""
    return cmd.replace(" ", "${IFS}") if " " in cmd and "'" not in cmd and '"' not in cmd else None


def ifs_bare(cmd: str) -> str | None:
    """rm$IFS$9-rf$IFS$9/  ($9 is empty, so $IFS is not glued to the next word)"""
    return cmd.replace(" ", "$IFS$9") if " " in cmd and "'" not in cmd and '"' not in cmd else None


def subshell_bash_c(cmd: str) -> str | None:
    """bash -c '<cmd>'"""
    return f"bash -c {shlex.quote(cmd)}"


def sh_c_dquote(cmd: str) -> str | None:
    """sh -c "<cmd>" """
    if any(c in cmd for c in '"$`\\'):
        return None
    return f'sh -c "{cmd}"'


def eval_wrap(cmd: str) -> str | None:
    """eval '<cmd>'"""
    return f"eval {shlex.quote(cmd)}"


def env_var_cmd(cmd: str) -> str | None:
    """X=rm; $X -rf /"""
    fw = _first_word(cmd)
    if not fw or not re.fullmatch(r"[A-Za-z0-9._/-]+", fw[0]):
        return None
    return f"X={fw[0]}; $X{fw[1]}"


def env_var_split(cmd: str) -> str | None:
    """a=r; b=m; $a$b -rf /"""
    fw = _first_word(cmd)
    if not fw or not fw[0].isalpha() or len(fw[0]) < 2:
        return None
    return f"a={fw[0][0]}; b={fw[0][1:]}; $a$b{fw[1]}"


def command_subst_word(cmd: str) -> str | None:
    """$(echo rm) -rf /"""
    fw = _first_word(cmd)
    if not fw or not fw[0].isalpha():
        return None
    return f"$(echo {fw[0]}){fw[1]}"


def backticks_word(cmd: str) -> str | None:
    """`echo rm` -rf /"""
    fw = _first_word(cmd)
    if not fw or not fw[0].isalpha():
        return None
    return f"`echo {fw[0]}`{fw[1]}"


def base64_pipe(cmd: str) -> str | None:
    """echo <b64> | base64 -d | sh"""
    return f"echo {base64.b64encode(cmd.encode()).decode()} | base64 -d | sh"


def base64_subst(cmd: str) -> str | None:
    """sh -c "$(echo <b64> | base64 -d)" """
    return f'sh -c "$(echo {base64.b64encode(cmd.encode()).decode()} | base64 -d)"'


def brace(cmd: str) -> str | None:
    """{rm,-rf,/}"""
    toks = cmd.split()
    if len(toks) < 2 or any(re.search(r"[\s'\"$`\;&|<>(){}*,]", t) for t in toks):
        return None
    return "{" + ",".join(toks) + "}"


def wrapper_env(cmd: str) -> str | None:
    """env FOO=1 nohup <cmd>"""
    return f"env FOO=1 nohup {cmd}"


def wrapper_command(cmd: str) -> str | None:
    """command <cmd>"""
    return f"command {cmd}"


def abs_path_argv0(cmd: str) -> str | None:
    """/bin/rm -rf /"""
    fw = _first_word(cmd)
    if not fw or not re.fullmatch(r"[a-z][a-z0-9-]*", fw[0]):
        return None
    return f"/usr/bin/{fw[0]}{fw[1]}"


def homoglyph(cmd: str) -> str | None:
    """Replace one Latin letter of the command word with a Cyrillic look-alike."""
    fw = _first_word(cmd)
    if not fw:
        return None
    w, rest = fw
    for i, ch in enumerate(w):
        if ch in _CYRILLIC:
            return w[:i] + _CYRILLIC[ch] + w[i + 1 :] + rest
    return None


def fullwidth(cmd: str) -> str | None:
    """Fullwidth Latin letters in the command word (NFKC folds them)."""
    fw = _first_word(cmd)
    if not fw or not fw[0].isalpha() or not fw[0].isascii():
        return None
    return "".join(chr(ord(c) + 0xFEE0) for c in fw[0]) + fw[1]


def zero_width(cmd: str) -> str | None:
    """Insert U+200B inside the command word."""
    fw = _first_word(cmd)
    if not fw or len(fw[0]) < 2:
        return None
    return fw[0][0] + "​" + fw[0][1:] + fw[1]


def noise_prefix(cmd: str) -> str | None:
    """true && <cmd>"""
    return f"true && {cmd}"


def noise_semicolon(cmd: str) -> str | None:
    """echo ok; <cmd>"""
    return f"echo ok; {cmd}"


def noise_pipe(cmd: str) -> str | None:
    """echo ok | <cmd>"""
    return None if "|" in cmd else f"echo ok | {cmd}"


def heredoc_shell(cmd: str) -> str | None:
    """bash <<'EOF' ... EOF"""
    return f"bash <<'EOF'\n{cmd}\nEOF"


def tabs(cmd: str) -> str | None:
    """Tabs instead of spaces."""
    return cmd.replace(" ", "\t") if " " in cmd and "'" not in cmd and '"' not in cmd else None


def newline_prefix(cmd: str) -> str | None:
    """ls\\n<cmd>"""
    return f"ls\n{cmd}"


def subshell_parens(cmd: str) -> str | None:
    """( <cmd> )"""
    return f"( {cmd} )"


def if_then(cmd: str) -> str | None:
    """if true; then <cmd>; fi"""
    return f"if true; then {cmd}; fi"


def xargs_wrap(cmd: str) -> str | None:
    """echo x | xargs <cmd>"""
    return None if "|" in cmd or ">" in cmd else f"echo x | xargs {cmd}"


ALL: dict[str, Gen] = {
    "quote_split": quote_split,
    "dquote_split": dquote_split,
    "backslash": backslash,
    "ansi_c": ansi_c,
    "octal": octal,
    "ifs": ifs,
    "ifs_bare": ifs_bare,
    "subshell_bash_c": subshell_bash_c,
    "sh_c_dquote": sh_c_dquote,
    "eval_wrap": eval_wrap,
    "env_var_cmd": env_var_cmd,
    "env_var_split": env_var_split,
    "command_subst_word": command_subst_word,
    "backticks_word": backticks_word,
    "base64_pipe": base64_pipe,
    "base64_subst": base64_subst,
    "brace": brace,
    "wrapper_env": wrapper_env,
    "wrapper_command": wrapper_command,
    "abs_path_argv0": abs_path_argv0,
    "homoglyph": homoglyph,
    "fullwidth": fullwidth,
    "zero_width": zero_width,
    "noise_prefix": noise_prefix,
    "noise_semicolon": noise_semicolon,
    "noise_pipe": noise_pipe,
    "heredoc_shell": heredoc_shell,
    "tabs": tabs,
    "newline_prefix": newline_prefix,
    "subshell_parens": subshell_parens,
    "if_then": if_then,
    "xargs_wrap": xargs_wrap,
}

# a smaller, representative set used by default in the corpus
CORE = [
    "quote_split",
    "ansi_c",
    "ifs",
    "subshell_bash_c",
    "env_var_cmd",
    "base64_pipe",
    "wrapper_env",
    "abs_path_argv0",
    "noise_semicolon",
    "heredoc_shell",
    "brace",
    "eval_wrap",
]


def variants(cmd: str, names: list[str] | None = None) -> list[tuple[str, str]]:
    """Return (generator name, obfuscated command) for each applicable generator."""
    out: list[tuple[str, str]] = []
    for n in names or list(ALL):
        v = ALL[n](cmd)
        if v is not None and v != cmd:
            out.append((n, v))
    return out
