"""
harness.py

Runs every attack against every defense configuration and prints two tables.

    Hijack rate   did the injected text steer the model at all
    Impact rate   did the attacker actually get the thing they wanted

The gap between those two columns is the finding.

Usage:
    python harness.py
    python harness.py --verbose
    python harness.py --decode-base64
"""

import argparse

from attacks import ATTACKS, attacker_won
from defenses import DEFENSE_STACKS
from vulnerable_app import DocAssistAgent

ORDER = ["none", "blocklist", "delimiting", "base64", "spotlighting",
         "least_privilege", "spotlight+privilege"]


def run_stack(name: str, decode_base64: bool, verbose: bool):
    cfg = DEFENSE_STACKS[name]
    agent = DocAssistAgent(
        input_defense=cfg["input_defense"],
        tool_policy=cfg["tool_policy"],
        decode_base64=decode_base64,
    )
    hijacked = 0
    impacted = 0
    rows = []
    for atk in ATTACKS:
        log = agent.run(atk.document, atk.user_request)
        won = attacker_won(atk, log)
        hijacked += int(log.hijacked)
        impacted += int(won)
        rows.append((atk, log, won))
        if verbose:
            status = "WON " if won else ("hijacked" if log.hijacked else "safe")
            print(f"    {atk.id} {status:<9} {atk.name}")
            if log.blocked_calls:
                print(f"         blocked at tool boundary: {log.blocked_calls}")
    return hijacked, impacted, rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--decode-base64", action="store_true",
                    help="let the mock model decode base64, to show that "
                         "encoding untrusted data is not a trust boundary")
    args = ap.parse_args()

    total = len(ATTACKS)
    print(f"\nPrompt Injection Lab: {total} attacks x "
          f"{len(ORDER)} configurations\n")
    print(f"{'defense':<22}{'hijack rate':>14}{'impact rate':>14}")
    print("-" * 50)

    results = {}
    for name in ORDER:
        if args.verbose:
            print(f"\n  [{name}]")
        h, i, _ = run_stack(name, args.decode_base64, args.verbose)
        results[name] = (h, i)
        if args.verbose:
            print()
        print(f"{name:<22}{h}/{total} ({h/total:>4.0%}){'':>3}"
              f"{i}/{total} ({i/total:>4.0%})")

    print("-" * 50)
    print("\nhijack rate = model followed injected text")
    print("impact rate = attacker obtained the secret or the action\n")

    base_i = results["none"][1]
    lp_h, lp_i = results["least_privilege"]
    best = min(results.items(), key=lambda kv: kv[1][1])
    print(f"Baseline impact: {base_i}/{total}. "
          f"Best configuration '{best[0]}': {best[1][1]}/{total}.")
    print(f"Least privilege alone leaves the hijack rate at "
          f"{lp_h}/{total} but cuts impact to {lp_i}/{total}: the model is "
          f"fooled every time and the damage is capped anyway.")
    print("Read the two columns together. A defense that only moves the "
          "hijack column is asking the model to be smarter. A defense that "
          "moves the impact column is removing authority the model never "
          "needed.\n")


if __name__ == "__main__":
    main()
