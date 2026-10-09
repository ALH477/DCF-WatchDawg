#!/usr/bin/env python3
"""Print the addresses in an nft set of table dcf_firewall, expanded, sorted, one per
line (ranges and prefixes are expanded: with `flags interval` nft merges neighbours).
Prints nothing and exits 0 for an empty set; exits 3 if the set does not exist."""
import ipaddress
import json
import subprocess
import sys

name = sys.argv[1]
r = subprocess.run(["nft", "-j", "list", "set", "ip", "dcf_firewall", name],
                   capture_output=True, text=True)
if r.returncode != 0:
    sys.stderr.write(r.stderr)
    sys.exit(3)
out = set()
for item in json.loads(r.stdout)["nftables"]:
    s = item.get("set")
    if not s:
        continue
    for e in s.get("elem", []):
        if isinstance(e, dict) and "elem" in e:
            e = e["elem"]["val"]
        if isinstance(e, str):
            out.add(int(ipaddress.IPv4Address(e)))
        elif "range" in e:
            lo, hi = (int(ipaddress.IPv4Address(x)) for x in e["range"])
            out.update(range(lo, hi + 1))
        elif "prefix" in e:
            net = ipaddress.IPv4Network("%s/%d" % (e["prefix"]["addr"], e["prefix"]["len"]))
            out.update(range(int(net.network_address), int(net.broadcast_address) + 1))
        else:
            raise SystemExit("nftset.py: unknown element %r" % (e,))
for v in sorted(out):
    print(ipaddress.IPv4Address(v))
