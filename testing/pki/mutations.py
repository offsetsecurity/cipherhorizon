#!/usr/bin/env python3
"""Mutation checks for PRD-004 T1 (QA-PLAN-004 §2).

Each mutation removes or weakens one guard in the source, runs the test that must
notice, and restores the file. A mutation that leaves the named test passing is a
gap in the tests. Run from the repository root:  python testing/pki/mutations.py
"""
import subprocess
import sys

MUTATIONS = [
    ("Missing intermediate: treat an AIA-reachable issuer as present",
     "internal/pki/chain.go",
     "\treturn true, top.Issuer.String(), top.IssuingCertificateURL",
     "\tif len(top.IssuingCertificateURL) > 0 {\n\t\treturn false, \"\", nil\n\t}\n\treturn true, top.Issuer.String(), top.IssuingCertificateURL",
     "./internal/eval/", "TestT1ChainMatrix"),
    ("Distrust-after: ignore the Mozilla constraint",
     "internal/pki/trust.go",
     "if !r.DistrustAfter.IsZero() && leaf.NotBefore.After(r.DistrustAfter) {",
     "if false && !r.DistrustAfter.IsZero() && leaf.NotBefore.After(r.DistrustAfter) {",
     "./internal/eval/", "TestT1TrustMatrix"),
    ("sct_not_after: ignore the Chrome constraint",
     "internal/pki/trust.go",
     "if !r.SCTNotAfter.IsZero() {",
     "if false && !r.SCTNotAfter.IsZero() {",
     "./internal/pki/", "TestValidate"),
    ("OCSP for this certificate: skip the serial/issuer-hash match",
     "internal/pki/ocsp.go",
     "if r.hash == 0 || !r.hash.Available() || r.Serial.Cmp(leaf.SerialNumber) != 0 {",
     "if len(o.Responses) > 0 {\n\t\t\treturn &o.Responses[0], true\n\t\t}\n\t\tif r.hash == 0 || !r.hash.Available() || r.Serial.Cmp(leaf.SerialNumber) != 0 {",
     "./internal/eval/", "TestT1RevocationMatrix"),
    ("OCSP signature: skip the check",
     "internal/pki/ocsp.go",
     "\tif issuer == nil {\n\t\treturn SigNoIssuer, nil\n\t}",
     "\tif issuer == nil {\n\t\treturn SigNoIssuer, nil\n\t}\n\tif o.tbs != nil {\n\t\treturn SigValid, nil\n\t}",
     "./internal/eval/", "TestT1RevocationMatrix"),
    ("Must-staple: drop the rule",
     "internal/eval/rules_t1.go",
     "ch.cr.Chain[0].OCSPMustStaple && ch.view.OCSP == nil",
     "false && ch.cr.Chain[0].OCSPMustStaple && ch.view.OCSP == nil",
     "./internal/eval/", "TestT1RevocationMatrix"),
    ("Lifetime limit: apply to private chains too",
     "internal/eval/pkiview.go",
     "lv := LifetimeView{Days: cr.Chain[0].LifetimeDays, Applies: ch.view.Public}",
     "lv := LifetimeView{Days: cr.Chain[0].LifetimeDays, Applies: true}",
     "./internal/eval/", "TestT1TrustMatrix"),
    ("Expiry scaling: revert to fixed 30/7 days",
     "internal/eval/rules_t1.go",
     "\tmedium, high = 30, 7\n\tif lifetime > 0 {",
     "\tmedium, high = 30, 7\n\tif false && lifetime > 0 {",
     "./internal/eval/", "TestT1ChainMatrix"),
    ("Anchor upload: accept key blocks",
     "internal/server/evaluate.go",
     "\tcase r.KeyBlocks > 0:",
     "\tcase false && r.KeyBlocks > 0:",
     "./internal/server/", "TestPrivateCATrustAnchors"),
    ("Target-only traffic: add a lookup of another host",
     "internal/tlsprobe/scan.go",
     "\tfor _, a := range all {\n\t\trep.Addresses = append(rep.Addresses, a.String())\n\t}",
     "\t_, _ = opts.LookupIP(ctx, \"ocsp.elsewhere.test\")\n\tfor _, a := range all {\n\t\trep.Addresses = append(rep.Addresses, a.String())\n\t}",
     "./internal/tlsprobe/", "TestTargetOnlyTraffic"),
    ("Parser bounds: remove a length check in the SCT decoder",
     "internal/pki/sct.go",
     "if n == 0 || n > len(b) {",
     "if n == 0 {",
     "./internal/pki/", "TestSCTList"),
    ("Labels not double-counted: make each label a finding of its own",
     "internal/eval/eval.go",
     "\tannotate(findings)\n",
     "\tannotate(findings)\n\tfor _, f := range findings {\n\t\tfor _, l := range f.Labels {\n\t\t\tfindings = append(findings, Finding{ID: \"ATTACK.\" + l, Title: l, Severity: f.Severity, Category: f.Category, Section: SecVulnerabilities})\n\t\t}\n\t}\n",
     "./internal/eval/", "TestLabelsDoNotChangeHygiene"),
]


def main():
    caught = 0
    for name, path, old, new, pkg, test in MUTATIONS:
        src = open(path, encoding="utf-8").read()
        if src.count(old) != 1:
            print(f"SETUP     {name}: the guarded code was not found exactly once in {path}")
            sys.exit(2)
        try:
            open(path, "w", encoding="utf-8", newline="\n").write(src.replace(old, new))
            r = subprocess.run(["go", "test", "-count=1", "-run", f"^{test}$", pkg], capture_output=True, text=True)
        finally:
            open(path, "w", encoding="utf-8", newline="\n").write(src)
        if r.returncode != 0:
            caught += 1
            print(f"CAUGHT    {name}  ->  {test} failed")
        else:
            print(f"MISSED    {name}  ->  {test} still passes")
    print(f"\nSUMMARY: {caught} of {len(MUTATIONS)} mutations caught")
    sys.exit(0 if caught == len(MUTATIONS) else 1)


if __name__ == "__main__":
    main()
