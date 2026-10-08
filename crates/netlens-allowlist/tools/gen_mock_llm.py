#!/usr/bin/env python3
"""Generate examples/troubleshoot/*/*/mock-llm.json: the scripted "model"
used by `netlens troubleshoot --mock-device DIR --model-url mock://` and the
end-to-end tests. Each script proposes the recorded commands, includes one
unsafe proposal (which the gate must reject), and ends with a final answer
whose evidence quotes are the scenario's key_evidence lines.

It is a script, not a model: it shows the plumbing (gate, approval, redaction,
syslog filter, citation validation), not diagnostic skill.
"""
import json, os, tomllib

ROOT = os.path.join(os.path.dirname(__file__), "..", "..", "..", "examples", "troubleshoot")

UNSAFE = {
    "ios/bgp-flap-mtu": ("clear ip bgp 198.51.100.2 soft", "Soft-reset the session to see if it recovers."),
    "ios/ospf-exstart-mtu": ("ping 203.0.113.21 size 1500 df-bit", "Probe the path MTU to the neighbor."),
    "ios/interface-errdisabled": ("configure terminal", "Bounce the port."),
    "eos/bgp-flap-crc": ("bash tcpdump -i et47", "Capture packets on the uplink."),
    "junos/bgp-auth-mismatch": ("show log messages | save /var/tmp/bgp.txt", "Keep a copy of the log."),
}
NEXT = {
    "ios": ["show ip bgp neighbors", "clear ip bgp *"],
    "eos": ["show interfaces counters errors"],
    "junos": ["show bgp neighbor"],
}

def main():
    for vendor in sorted(os.listdir(ROOT)):
        for name in sorted(os.listdir(os.path.join(ROOT, vendor))):
            d = os.path.join(ROOT, vendor, name)
            key = f"{vendor}/{name}"
            with open(os.path.join(d, "scenario.toml"), "rb") as f:
                s = tomllib.load(f)
            syslog = open(os.path.join(d, s["syslog"])).read().splitlines()
            ev_files = {e["file"] for e in s["key_evidence"]}
            cmds = [c for c in s["commands"] if c["file"] in ev_files]
            for c in s["commands"]:
                if len(cmds) >= 6:
                    break
                if c not in cmds:
                    cmds.append(c)
            cmds.sort(key=lambda c: s["commands"].index(c))
            replies, step, step_of = [], 0, {}
            for i, c in enumerate(cmds):
                if i == 1:
                    step += 1
                    cmd, why = UNSAFE[key]
                    replies.append({"action": "run", "command": cmd, "reason": why})
                step += 1
                step_of[c["file"]] = step
                replies.append({"action": "run", "command": c["command"],
                                "reason": f"Check `{c['command']}` for evidence about the symptom."})
            evidence = []
            for e in s["key_evidence"]:
                if e["file"] == s["syslog"]:
                    n = syslog.index(e["line"]) + 1
                    evidence.append({"cite": f"L{n}", "quote": e["line"].strip()})
                else:
                    evidence.append({"cite": f"O{step_of[e['file']]}", "quote": e["line"].strip()})
            if key == "ios/bgp-flap-mtu":
                # A fabricated quote: netlens must drop it.
                evidence.append({"cite": "O3", "quote": "BGP neighbor reset by operator"})
            final = {"action": "final", "root_cause": s["root_cause"]["text"],
                     "confidence": "high", "evidence": evidence,
                     "next_checks": NEXT[vendor]}
            out = {"_comment": "Scripted replies for netlens' offline mock model (not a real model). "
                               "Regenerate with crates/netlens-allowlist/tools/gen_mock_llm.py.",
                   "root_cause_id": s["root_cause"]["id"],
                   "replies": replies + [final]}
            if key == "eos/bgp-flap-crc":
                # Show that <think> blocks and code fences around the JSON are tolerated.
                out["replies"][0] = "<think>Start with the BGP summary.</think>\n```json\n" + json.dumps(out["replies"][0]) + "\n```"
            with open(os.path.join(d, "mock-llm.json"), "w") as f:
                json.dump(out, f, indent=2)
                f.write("\n")
            print(key, len(replies), "commands,", len(evidence), "evidence")

if __name__ == "__main__":
    main()
