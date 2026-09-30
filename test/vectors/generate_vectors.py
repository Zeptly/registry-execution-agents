#!/usr/bin/env python3
"""Generates the language-neutral golden vectors in this directory (parser.json, canonicalization.json, digest.json).
Independent of the JavaScript implementation: hashing with hashlib, own RFC 8785-style serializer (UTF-16 code-unit key order).
Expected values for numbers with exponents are literal strings taken from RFC 8785 (Python float formatting differs), and are
verified in CI against the RFC author's reference implementation. Run:  python3 test/vectors/generate_vectors.py
These are REGISTRY-LOCAL vectors authored against the Protocol v0.2 amendment text; replace/extend with the protocol
distribution's shared vectors when they are supplied."""
import json, hashlib, os, copy
HERE = os.path.dirname(os.path.abspath(__file__))
ALG = "zeptly-jcs-v1"
sha = lambda b: "sha256:" + hashlib.sha256(b).hexdigest()

def jcs(o):
    if isinstance(o, dict): return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + jcs(o[k]) for k in sorted(o, key=lambda k: k.encode("utf-16-be"))) + "}"
    if isinstance(o, list): return "[" + ",".join(jcs(x) for x in o) + "]"
    if isinstance(o, bool): return "true" if o else "false"
    if o is None: return "null"
    if isinstance(o, int): return str(o)
    if isinstance(o, float): assert "e" not in repr(o), "exponent floats must use literal expectations"; return repr(o)
    return json.dumps(o, ensure_ascii=False)
def hexof(s): return s.encode("utf-8").hex()

# ---------------- canonicalization
canon = []
def add(name, json_text, expected, source, note=""):
    canon.append({"name": name, "json": json_text, "canonical": expected, "canonicalUtf8Hex": hexof(expected), "sha256": sha(expected.encode()), "expectedSource": source, "note": note})
rfc = {"\u20ac": "Euro Sign", "\r": "Carriage Return", "\ufb33": "Hebrew Letter Dalet With Dagesh", "1": "One", "\U0001F600": "Emoji: Grinning Face", "\u0080": "Control", "\u00f6": "Latin Small Letter O With Diaeresis"}
add("rfc8785-sorting", json.dumps(rfc), jcs(rfc), "RFC 8785 §3.2.3 input; order computed by UTF-16 code units", "emoji (surrogate pair D83D) sorts before U+FB33 in UTF-16 order")
add("rfc8785-numbers", "[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001]", "[333333333.3333333,1e+30,4.5,0.002,1e-27]", "RFC 8785 Appendix B values (literal)")
add("nested-structure-order", '{"b":[true,null,{"z":1,"a":[]}],"a":{}}', '{"a":{},"b":[true,null,{"a":[],"z":1}]}', "independent serializer")
add("no-unicode-normalization", json.dumps(["\u00e9", "e\u0301"], ensure_ascii=True), jcs(["\u00e9", "e\u0301"]), "independent serializer", "NFC and NFD forms stay distinct")
add("string-escapes", json.dumps(["\u0001\u001f\"\\/\n\t", "\u2028\u007f"], ensure_ascii=True), jcs(["\u0001\u001f\"\\/\n\t", "\u2028\u007f"]), "independent serializer", "controls escaped lowercase \\u00xx; U+2028 and DEL raw; '/' unescaped")
add("astral-raw", json.dumps(["\U0001F600"], ensure_ascii=True), jcs(["\U0001F600"]), "independent serializer")
add("negative-zero", "[-0,0,1,-1,1.5,100]", "[0,0,1,-1,1.5,100]", "RFC 8785 (ECMAScript number serialization)")
add("empty-structures", '{"a":[],"b":{}}', '{"a":[],"b":{}}', "independent serializer")
canon_reject = [{"name": "lone-surrogate-string", "json": '"\\ud800"', "code": "lone-surrogate"},
                {"name": "lone-surrogate-key", "json": '{"\\udc00":1}', "code": "lone-surrogate"}]
json.dump({"digestAlgorithm": ALG, "accept": canon, "reject": canon_reject}, open(f"{HERE}/canonicalization.json", "w"), indent=2, ensure_ascii=True); open(f"{HERE}/canonicalization.json", "a").write("\n")

# ---------------- parser (JSON-compatible YAML subset)
P = []
def ok(name, y, value): P.append({"name": name, "yaml": y, "valid": True, "value": value, "canonical": jcs(value)})
def bad(name, y, code): P.append({"name": name, "yaml": y, "valid": False, "code": code})
def badbytes(name, h, code): P.append({"name": name, "bytesHex": h, "valid": False, "code": code})
ok("scalars", "a: 1\nb: 0.05\nc: -0\nd: 1e-7\ne: 2.5e3\nf: 9007199254740991\ng: -9007199254740991\nh: hello\ni: ~\nj: true\n", {"a": 1, "b": 0.05, "c": 0, "d": None, "e": 2500, "f": 9007199254740991, "g": -9007199254740991, "h": "hello", "i": None, "j": True})
P[-1]["value"]["d"] = 1e-07; P[-1]["canonical"] = '{"a":1,"b":0.05,"c":0,"d":1e-7,"e":2500,"f":9007199254740991,"g":-9007199254740991,"h":"hello","i":null,"j":true}'
ok("timestamps-and-yes-no-are-strings", "a: 2026-01-01T00:00:00Z\nb: yes\nc: off\nd: No\n", {"a": "2026-01-01T00:00:00Z", "b": "yes", "c": "off", "d": "No"})
ok("quoted-merge-token-is-a-string", 'a: "<<"\n"<<": 1\n', {"a": "<<", "<<": 1})
ok("explicit-core-tags", "a: !!str 1\nb: !!int 5\nc: !!map {k: 1}\nd: !!seq [1]\n", {"a": "1", "b": 5, "c": {"k": 1}, "d": [1]})
ok("flow-and-unicode", 'a: [1, {b: "caf\u00e9"}]\n', {"a": [1, {"b": "caf\u00e9"}]})
ok("empty-document", "", None)
for n, y, c in [
    ("duplicate-key", "a: 1\na: 2\n", "yaml-duplicate-key"), ("anchor", "a: &x 1\n", "yaml-anchor"), ("alias", "a: &x 1\nb: *x\n", "yaml-alias"),
    ("merge-key", "a: {k: 1}\nb:\n  <<: {j: 2}\n", "yaml-merge-key"), ("multiple-documents", "a: 1\n---\nb: 2\n", "yaml-multiple-documents"),
    ("non-string-key-int", "1: x\n", "yaml-non-string-key"), ("non-string-key-bool", "true: x\n", "yaml-non-string-key"), ("non-string-key-null", "? ~\n: x\n", "yaml-non-string-key"),
    ("unsupported-tag-binary", "a: !!binary aGk=\n", "yaml-unsupported-tag"), ("unsupported-tag-timestamp", "a: !!timestamp 2026-01-01\n", "yaml-unsupported-tag"), ("unsupported-tag-custom", "a: !foo 1\n", "yaml-unsupported-tag"),
    ("hex-integer", "a: 0x10\n", "yaml-number-not-json"), ("octal-integer", "a: 0o17\n", "yaml-number-not-json"), ("plus-sign", "a: +1\n", "yaml-number-not-json"),
    ("leading-dot", "a: .5\n", "yaml-number-not-json"), ("trailing-dot", "a: 5.\n", "yaml-number-not-json"), ("leading-zero", "a: 007\n", "yaml-number-not-json"),
    ("infinity", "a: .inf\n", "yaml-non-finite-number"), ("nan", "a: .nan\n", "yaml-non-finite-number"),
    ("unsafe-integer", "a: 9007199254740993\n", "yaml-unsafe-integer"), ("unsafe-integer-boundary", "a: 9007199254740992\n", "yaml-unsafe-integer"), ("negative-unsafe-integer", "a: -9007199254740992\n", "yaml-unsafe-integer"),
    ("unsafe-integer-point-zero", "a: 9007199254740993.0\n", "yaml-unsafe-integer"), ("unsafe-integer-exponent", "a: 9007199254740993e0\n", "yaml-unsafe-integer"),
    ("unsafe-integer-negative-exponent", "a: 90071992547409930e-1\n", "yaml-unsafe-integer"), ("unsafe-1e16", "a: 1e16\n", "yaml-unsafe-integer"), ("unsafe-1e21", "a: 1e21\n", "yaml-unsafe-integer"),
    ("nul-escape", 'a: "x\\0y"\n', "nul-byte"), ("lone-surrogate-escape", 'a: "\\ud800"\n', "lone-surrogate"), ("syntax-error", "a: [1\n", "yaml-invalid"),
]: bad(n, y, c)
badbytes("invalid-utf8", "613a20ff0a", "utf8-invalid"); badbytes("bom", "efbbbf613a20310a", "utf8-bom"); badbytes("raw-nul", "613a203100", "nul-byte")
badbytes("crlf", "613a20310d0a", "line-ending-cr"); badbytes("lone-cr", "613a20310d", "line-ending-cr")
ok("fractional-near-unsafe", "a: 9007199254740993.5\nb: 123456789012345678e-2\n", {"a": 9007199254740994.0, "b": 1234567890123456.8})
P[-1]["canonical"] = '{"a":9007199254740994,"b":1234567890123456.8}'; P[-1]["note"] = "fractional literals keep their (rounded) double value; only integer-valued literals are rejected"
json.dump({"digestAlgorithm": ALG, "cases": P}, open(f"{HERE}/parser.json", "w"), indent=2, ensure_ascii=True); open(f"{HERE}/parser.json", "a").write("\n")

# ---------------- digest / seal
art = {"apiVersion": "registry.zeptly.dev/v1alpha1", "kind": "ExecutionAgent",
       "metadata": {"id": "golden.vector", "version": "9.9.9", "registry": "execution-agents", "origin": {"type": "native"}, "maturity": "candidate", "lifecycle": "active"},
       "spec": {"name": "Golden", "ratio": 0.05, "steps": [1, 2, 3], "text": "caf\u00e9", "runtimeApprovals": [{"before": "posting", "approver": "workspace_member"}]},
       "references": [{"registry": "skills", "id": "source-evaluation", "version": "1.0.0", "digest": "sha256:" + "a" * 64, "digestAlgorithm": ALG}],
       "provenance": {"createdAt": "2026-01-01T00:00:00Z", "authors": ["github:golden"], "sourceRefs": [], "transformations": [], "synthetic": True},
       "security": {"classification": "internal", "capabilities": [{"registry": "capabilities", "id": "knowledge.search", "version": "1.0.0"}], "approvals": []},
       "attestations": []}
def projection(a): return {"apiVersion": a["apiVersion"], "kind": a["kind"], "metadata": {"id": a["metadata"]["id"], "registry": a["metadata"]["registry"], "origin": a["metadata"]["origin"]},
                            "spec": a["spec"], "references": a["references"], "provenance": a["provenance"], "security": {"classification": a["security"]["classification"], "capabilities": a["security"]["capabilities"]}}
def digests(a, payload):
    ad = sha(jcs(projection(a)).encode())
    entries = [{"path": p, "sha256": sha(c.encode())} for p, c in sorted(payload.items())]
    sd = sha(jcs({"registry": a["metadata"]["registry"], "id": a["metadata"]["id"], "version": a["metadata"]["version"], "payload": entries}).encode())
    return ad, sd, entries
payload = {"prompts/system.md": "Golden prompt\n", "contracts/input.schema.json": '{"type":"object"}\n', "evals/golden.yaml": "apiVersion: registry.zeptly.dev/v1alpha1\nkind: EvaluationSuite\nid: golden\nversion: 1.0.0\ncases: []\n"}
ad, sd, entries = digests(art, payload)
def apply(a, p, spec):
    """Structured mutation spec (language-neutral): set / append on the artifact, payloadSet / payloadDelete on payload files."""
    if "set" in spec:
        d = a
        for k in spec["set"]["path"][:-1]: d = d[k]
        d[spec["set"]["path"][-1]] = spec["set"]["value"]
    elif "append" in spec:
        d = a
        for k in spec["append"]["path"]: d = d[k]
        d.append(spec["append"]["value"])
    elif "payloadSet" in spec: p[spec["payloadSet"]["path"]] = spec["payloadSet"]["content"]
    elif "payloadDelete" in spec: p.pop(spec["payloadDelete"])
def variant(name, spec):
    a = copy.deepcopy(art); p = dict(payload); apply(a, p, spec)
    va, vs, _ = digests(a, p)
    return {"name": name, "mutation": spec, "artifactDigestChanges": va != ad, "sealDigestChanges": vs != sd, "artifactDigest": va, "sealDigest": vs}
S = lambda path, value: {"set": {"path": path, "value": value}}
variants = [
    variant("version-only", S(["metadata", "version"], "9.9.10")),
    variant("maturity", S(["metadata", "maturity"], "canonical")),
    variant("lifecycle-marker", S(["metadata", "lifecycle"], "deprecated")),
    variant("attestation-appended", {"append": {"path": ["attestations"], "value": {"type": "provenance", "ref": "evidence://x", "subjectDigest": ad, "sealDigest": sd}}}),
    variant("governance-approval-appended", {"append": {"path": ["security", "approvals"], "value": {"type": "promotion", "approver": "team:x", "approvedAt": "2026-01-01T00:00:00Z", "subjectDigest": ad, "sealDigest": sd}}}),
    variant("identity-id", S(["metadata", "id"], "golden.other")),
    variant("origin", S(["metadata", "origin"], {"type": "upstream-seed", "import": {"source": "upstream-x"}})),
    variant("spec-value", S(["spec", "ratio"], 0.06)),
    variant("runtime-approval-requirement", S(["spec", "runtimeApprovals"], [])),
    variant("references", S(["references"], [])),
    variant("provenance", S(["provenance", "authors"], ["github:golden", "github:other"])),
    variant("classification", S(["security", "classification"], "restricted")),
    variant("capabilities", S(["security", "capabilities"], [])),
    variant("payload-mutation", {"payloadSet": {"path": "prompts/system.md", "content": "Changed prompt\n"}}),
    variant("payload-deletion", {"payloadDelete": "evals/golden.yaml"}),
    variant("payload-added", {"payloadSet": {"path": "prompts/extra.md", "content": "x\n"}}),
]
line_endings = [{"name": "crlf-payload", "path": "prompts/system.md", "bytesHex": b"a\r\nb\n".hex(), "code": "line-ending-cr"}, {"name": "lone-cr-payload", "path": "prompts/system.md", "bytesHex": b"a\rb\n".hex(), "code": "line-ending-cr"}]
json.dump({"digestAlgorithm": ALG, "artifact": art, "payload": payload,
           "expected": {"projectionCanonical": jcs(projection(art)), "artifactDigest": ad, "payloadEntries": entries,
                        "sealInputCanonical": jcs({"registry": art["metadata"]["registry"], "id": art["metadata"]["id"], "version": art["metadata"]["version"], "payload": entries}), "sealDigest": sd},
           "variants": variants, "lineEndingRejections": line_endings}, open(f"{HERE}/digest.json", "w"), indent=2, ensure_ascii=True); open(f"{HERE}/digest.json", "a").write("\n")
print("artifactDigest", ad); print("sealDigest", sd)
