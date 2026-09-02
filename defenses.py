"""
defenses.py

Four mitigations, ordered weakest to strongest. The point of the repo is
that the first three are prompt-layer patches and the last one is not, and
that this difference is what actually shows up in the numbers.
"""

import base64
import re

# ---------------------------------------------------------------------------
# 1. Blocklist filter. The fix everybody reaches for first.
# ---------------------------------------------------------------------------

BLOCKED = [
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions",
    r"disregard\s+(?:the\s+)?(?:above|system)",
    r"new\s+instructions",
]


def blocklist_filter(document: str) -> str:
    """
    Strip known attack phrases.

    Why it fails: it matches strings, but the model understands meaning.
    Any rephrasing that a human would still read as an override sails
    straight through, and so does spacing or homoglyph obfuscation, because
    the filter sees raw bytes while the model effectively sees normalized
    text. This is the LLM version of blocking "' OR 1=1" instead of using
    parameterized queries.
    """
    out = document
    for pattern in BLOCKED:
        out = re.sub(pattern, "[filtered]", out, flags=re.IGNORECASE)
    return out


# ---------------------------------------------------------------------------
# 2. Delimiting. Wrap the untrusted part and tell the model where it ends.
# ---------------------------------------------------------------------------

def delimiting(document: str) -> str:
    """
    Fence the document so the model knows it is data.

    Why it fails: the fence is made of the same characters the attacker can
    write. Emit a closing tag inside the document and you are back outside
    the fence. Same class of bug as SQL injection via an unescaped quote.
    """
    return f"<document>\n{document}\n</document>"


# ---------------------------------------------------------------------------
# 3. Spotlighting. Mark untrusted text so it is structurally inert.
# ---------------------------------------------------------------------------

SPOTLIGHT = "\u2999"


def spotlighting(document: str) -> str:
    """
    Wrap untrusted data in markers the attacker cannot forge, after
    stripping any attempt to inject those markers.

    This one mostly works, because the marker is stripped from attacker
    content before it is applied. It is still a prompt-layer control, so it
    depends on the model honoring it, and a model that decides to read the
    inert region anyway defeats it.
    """
    cleaned = document.replace(SPOTLIGHT, "")
    return f"{SPOTLIGHT}{cleaned}{SPOTLIGHT}"


def base64_encoding(document: str) -> str:
    """
    Encode untrusted data so injected text is not literal instruction text.

    Included specifically to show a defense that LOOKS strong and is not.
    Capable models decode base64 happily. Run the harness with
    decode_base64=True to watch this one collapse.
    """
    return base64.b64encode(document.encode()).decode()


# ---------------------------------------------------------------------------
# 4. Least privilege. Not a prompt-layer control at all.
# ---------------------------------------------------------------------------

ALLOWED_RECIPIENTS = {"user@company.example"}


def least_privilege_policy(tool: str, args: dict) -> bool:
    """
    Decide whether a requested action is permitted, regardless of why the
    model requested it.

    This does not try to stop the model from being fooled. It assumes the
    model WILL be fooled and caps the damage. A summarizing task has no
    business emailing strangers or reading arbitrary paths, so those calls
    are refused at the tool boundary where the attacker has no say.

    This is the actual lesson of the repo: you do not fix prompt injection
    in the prompt. You fix it by not handing the model authority it does not
    need for the task in front of it.
    """
    if tool == "send_email":
        return args.get("to") in ALLOWED_RECIPIENTS
    if tool == "read_file":
        return str(args.get("path", "")).startswith("docs/")
    return False


def permissive_policy(tool: str, args: dict) -> bool:
    """The vulnerable default: the model asked, so we do it."""
    return True


DEFENSE_STACKS = {
    "none": dict(input_defense=None, tool_policy=permissive_policy),
    "blocklist": dict(input_defense=blocklist_filter,
                      tool_policy=permissive_policy),
    "delimiting": dict(input_defense=delimiting,
                       tool_policy=permissive_policy),
    "spotlighting": dict(input_defense=spotlighting,
                         tool_policy=permissive_policy),
    "base64": dict(input_defense=base64_encoding,
                   tool_policy=permissive_policy),
    "least_privilege": dict(input_defense=None,
                            tool_policy=least_privilege_policy),
    "spotlight+privilege": dict(input_defense=spotlighting,
                                tool_policy=least_privilege_policy),
}
