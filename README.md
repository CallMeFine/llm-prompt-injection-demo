# LLM Prompt Injection Lab

A deliberately vulnerable LLM agent, a corpus of injection attacks against it,
and measurements of which defenses actually reduce impact.

Runs on a deterministic mock model. No API keys, no dependencies, no network
calls. `python harness.py` and you have the results table below.

## What this is not

This is not a jailbreak collection. There are no payloads here aimed at any
commercial model, and none of the attacks in `attacks.py` will do anything to
anything except the toy app in `vulnerable_app.py`. The interesting part of
prompt injection is not the payload, it is which mitigations survive contact
with one.

## The bug

If you have written SQL injection exercises, you already know this bug.

A SQL injection happens because a query string mixes trusted structure with
untrusted values, and the database cannot tell which is which. Prompt injection
happens for exactly the same reason: the model gets one flat string containing
both the developer's instructions and third-party content, and there is nothing
in the format that marks the boundary.

```python
prompt = f"{SYSTEM_PROMPT}\n\nUSER: {user_request}\n\nRETRIEVED DOCUMENT:\n{document}"
```

That is the whole vulnerability. `document` came from an upload, a web page, an
email, a shared drive. Whoever controls it controls part of the instruction
channel.

The difference from SQL injection is that SQL has a real fix. You can
parameterize a query, because SQL has a formal grammar and the value slot is
structurally distinct from the code slot. Natural language has no such grammar.
That is why the defenses below behave the way they do.

## Threat model

| | |
|---|---|
| Asset | A secret in the system prompt, and two tools the agent can call |
| Trusted | The system prompt, written by the developer |
| Untrusted | The document body, from any third party |
| Attacker | Can write arbitrary text into a document the agent will later read. Cannot see the system prompt, modify the code, or observe the model's weights |
| Goal | Read the secret, or make the agent take an action on the attacker's behalf |

Attack A01 is the one exception: it comes through the user turn rather than the
document. It is included as a severity contrast, since a user attacking an agent
that acts on their own behalf is a much smaller problem than a stranger doing it
through a document.

## Running it

```bash
git clone https://github.com/CallMeFine/llm-prompt-injection-demo
cd llm-prompt-injection-demo
python harness.py              # the table
python harness.py --verbose    # per-attack breakdown
python harness.py --decode-base64
```

Python 3.7 or newer. Standard library only.

## Results

8 attacks, 7 configurations.

| Defense | Hijack rate | Impact rate |
|---|---|---|
| none (baseline) | 8/8 (100%) | 8/8 (100%) |
| blocklist filter | 8/8 (100%) | 8/8 (100%) |
| delimiting | 2/8 (25%) | 2/8 (25%) |
| base64 encoding | 1/8 (12%) | 1/8 (12%) |
| base64, model decodes it | 8/8 (100%) | 8/8 (100%) |
| spotlighting | 1/8 (12%) | 1/8 (12%) |
| least privilege only | 8/8 (100%) | 6/8 (75%) |
| spotlighting + least privilege | 1/8 (12%) | 1/8 (12%) |

**Hijack rate** is how often the injected text steered the model at all.
**Impact rate** is how often the attacker got the secret or the action.

Keeping those two columns separate is the point of the whole exercise.

## Reading the table

**The blocklist does nothing.** 100 percent to 100 percent. It matches strings
while the model responds to meaning, so A02 rewords the request and walks past
it, and A04 offers up a blocked phrase as a decoy while keeping the real
directive in the next sentence. A05 and A06 defeat it with letter spacing and
Cyrillic homoglyphs, which change the bytes without changing what a model reads.
This is the same reason blocking `' OR 1=1` is not an SQL injection fix.

**Delimiting works until the attacker writes the closing tag.** It drops impact
to 25 percent, and the two survivors are A01 and A03. A03 is the interesting one:
the payload emits its own `</document>`, the fence closes early, and everything
after it is back in the instruction channel. An unescaped delimiter, which is
the oldest injection bug there is.

**Base64 is the trap.** It looks like the best defense in the table at 12
percent, and it collapses to 100 percent the moment the model is allowed to
decode it, which capable models do without being asked. Encoding is obfuscation,
not a trust boundary. This row exists to show a defense that measures well and
is worthless.

**Least privilege never stops the hijack, and that is fine.** The model is fooled
in all 8 cases. But A07's email to `exfil@attacker.example` and A08's traversal
to `../../etc/secrets.env` get refused at the tool boundary, where the attacker
has no vote. The agent was compromised and the attacker still got nothing from
those two.

The residual 6/8 is the system prompt leak, which least privilege does not touch,
because the secret was sitting in the prompt where the model could read it. The
fix for that is not a better prompt, it is not putting a credential in the
context window at all.

## Limitations

The mock model follows the last matching instruction it finds. Real models are
probabilistic and safety-trained, so real attack success rates land between 0
and 100 rather than on clean values, and some of these payloads would simply be
refused.

The spotlighting row is the number to distrust. It scores 12 percent because the
mock honors the inert-data marker by construction. A real model has no such
guarantee, and published results on spotlighting show meaningful bypass rates.
Treat 12 percent as the ceiling of what the technique could do, not as a
measurement of what it does.

The least privilege row does not have this problem, which is the argument for it.
Its effect does not depend on the model's cooperation at all.

## Scope and disclosure

Every attack targets `vulnerable_app.py` in this repository. No commercial or
third-party model was tested, probed, or used to develop these payloads, and
nothing here constitutes a working exploit against any deployed system.

## References

- OWASP Top 10 for LLM Applications, LLM01 Prompt Injection and LLM06 Excessive Agency
- Greshake et al., *Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection* (2023)
- Hines et al., *Defending Against Indirect Prompt Injection Attacks With Spotlighting* (Microsoft, 2024)
- Simon Willison's ongoing writing on prompt injection and the lethal trifecta

## Layout

```
mock_llm.py         deterministic fake model, models one failure mode
vulnerable_app.py   the target agent, defenses injected not hardcoded
attacks.py          8 payloads, mapped to OWASP LLM Top 10
defenses.py         4 mitigations plus the policy layer
harness.py          runs everything, prints the table
```
