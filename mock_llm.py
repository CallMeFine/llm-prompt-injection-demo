"""
mock_llm.py

A deterministic stand-in for a real LLM.

WHY A FAKE MODEL
----------------
Prompt injection does not need a real model to demonstrate. The bug is
architectural: the model receives ONE flat string, and that string mixes
trusted developer instructions with untrusted third-party data. Nothing in
the format tells the model which is which.

This mock reproduces exactly that property and nothing else. It is not a
language model and it does not pretend to be one. It is a parser with one
rule:

    Scan the whole prompt for instruction-shaped text. If several are
    found, the LAST one wins.

"Last one wins" is not arbitrary. Real transformer models show recency bias
toward instructions late in the context, which is a large part of why
injected text placed after the system prompt is effective.

WHAT THIS MOCK CANNOT SHOW
--------------------------
Real models are probabilistic, so real attack success rates sit somewhere
between 0 and 100 percent rather than landing on clean values. Real models
also refuse some attacks outright through safety training. Treat the
numbers here as a measure of whether a DEFENSE closes a structural hole,
not as a prediction of any real model's success rate.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field


@dataclass
class ModelResponse:
    """What the mock 'model' decided to do."""
    action: str                       # summarize | leak_system_prompt | call_tool
    tool: str | None = None
    tool_args: dict = field(default_factory=dict)
    matched_text: str = ""            # the directive that won, for debugging


# The tiny instruction set this mock understands. Each entry is a regex and
# the action it maps to. Real models understand open-ended language; this is
# a deliberate simplification so results are reproducible.
DIRECTIVES = [
    (r"summari[sz]e\b", lambda m: ModelResponse("summarize")),
    (
        r"(?:reveal|print|repeat|output|show)\s+(?:your\s+|the\s+)?"
        r"(?:system\s+prompt|instructions|rules)",
        lambda m: ModelResponse("leak_system_prompt"),
    ),
    (
        r"(?:send|email|forward)\s+(?:an?\s+)?(?:email\s+)?to\s+"
        r"([\w.+-]+@[\w.-]+)",
        lambda m: ModelResponse("call_tool", tool="send_email",
                                tool_args={"to": m.group(1)}),
    ),
    (
        r"(?:read|open|fetch|cat)\s+(?:the\s+)?file\s+([\w./-]+)",
        lambda m: ModelResponse("call_tool", tool="read_file",
                                tool_args={"path": m.group(1)}),
    ),
]

# Text between these markers is treated as inert data, never as instructions.
# This is what the "spotlighting" defense relies on.
SPOTLIGHT_RE = re.compile(r"\u2999(.*?)\u2999", re.DOTALL)

# An XML-style fence. Non-greedy on purpose: the fence ends at the FIRST
# closing tag, which is precisely why an attacker who writes their own
# closing tag lands outside the fence. This models a cooperative model that
# honors the delimiter exactly as instructed.
DELIM_RE = re.compile(r"<document>(.*?)</document>", re.DOTALL)


def _normalize(text: str) -> str:
    """
    Fold away the cheap obfuscation tricks a model would see through anyway.

    A real model reads 'i g n o r e' and 'іgnore' (Cyrillic i) the same as
    'ignore'. A naive regex blocklist does not. Normalizing here is what
    makes the blocklist defense in defenses.py fail realistically instead of
    looking stronger than it is.
    """
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    homoglyphs = {"\u0456": "i", "\u0430": "a", "\u0435": "e",
                  "\u043e": "o", "\u0440": "p", "\u0441": "c"}
    for bad, good in homoglyphs.items():
        text = text.replace(bad, good)
    # collapse letter s p a c i n g
    text = re.sub(r"\b(?:\w\s){2,}\w\b",
                  lambda m: m.group(0).replace(" ", ""), text)
    return text


class MockLLM:
    """A fake model whose only flaw is the one we want to study."""

    def __init__(self, decode_base64: bool = False):
        # If the app base64-encodes untrusted data, a real model can often
        # still decode it. Flip this on to show that encoding alone is not a
        # boundary, it is an inconvenience.
        self.decode_base64 = decode_base64

    def generate(self, prompt: str) -> ModelResponse:
        scannable = self._scannable_text(prompt)
        best = None
        best_pos = -1
        for pattern, build in DIRECTIVES:
            for m in re.finditer(pattern, scannable, re.IGNORECASE):
                if m.start() > best_pos:
                    best_pos = m.start()
                    resp = build(m)
                    resp.matched_text = m.group(0)
                    best = resp
        return best or ModelResponse("summarize", matched_text="<default>")

    def _scannable_text(self, prompt: str) -> str:
        """Everything the model will actually read instructions out of."""
        # Spotlighted regions are structurally inert: the model was handed
        # them as opaque data, not as part of the instruction channel.
        text = SPOTLIGHT_RE.sub(" [INERT DATA] ", prompt)
        text = DELIM_RE.sub(" [FENCED DATA] ", text)
        if self.decode_base64:
            text = self._decode_blobs(text)
        return _normalize(text)

    @staticmethod
    def _decode_blobs(text: str) -> str:
        def sub(m):
            try:
                return m.group(0) + " " + base64.b64decode(
                    m.group(0)).decode("utf-8", "ignore")
            except Exception:
                return m.group(0)
        return re.sub(r"[A-Za-z0-9+/]{24,}={0,2}", sub, text)
