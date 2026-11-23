#!/usr/bin/env python3
"""prep_redact.py: the back-edge cut that has to land before observability (and hooks) can move.

Credential redaction lives inside the agent loop (`agent/turn/redact.rs`, plus
`scrub_for_export` in `agent/loop_.rs`) but is called from observability, hooks and
SOP, which sit below the agent. This recipe gives redaction one owner in a lower
crate, next to the existing `scrub_secret_patterns`, and leaves a re-export at each
old path so no other caller changes:

  * `agent/turn/redact.rs`                       -> `zeroclaw-providers/src/redact.rs` (git mv)
  * `approval::looks_like_secret_key`            -> same file (re-exported from `approval`)
  * `agent::loop_::{IMAGE_DATA_URI_REGEX, elide_image_data, scrub_for_export}` -> same file
  * observability and hooks import the new path directly (they are the two modules
    that must stop naming `crate::agent`).

No behaviour changes: every function body is moved verbatim. Matching is by content,
not line number, so the recipe can be re-run on a newer base; it fails loudly if a
block it expects is no longer there.

The prototype uses `zeroclaw-providers` because `scrub_for_export` composes
`zeroclaw_providers::scrub_secret_patterns`. `zeroclaw-infra` is the other
candidate home; that would mean moving `scrub_secret_patterns` down as well.
"""
import os
import re
import subprocess
import sys

repo = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
RT = os.path.join(repo, "crates/zeroclaw-runtime/src")
PV = os.path.join(repo, "crates/zeroclaw-providers/src")


def read(p):
    return open(p, encoding="utf-8").read()


def write(p, s):
    open(p, "w", encoding="utf-8").write(s)


def blank_tests(text):
    """Production view of a file: comments, strings and #[cfg(test)] items blanked."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from modgraph2 import blank, strip_tests
    return strip_tests(text, blank(text))[0]


def cut(text, start_pat, end_pat, what):
    """Remove and return the block from the line matching start_pat through the line matching end_pat."""
    m = re.search(start_pat, text, re.M)
    if not m:
        sys.exit("prep_redact: cannot find %s" % what)
    e = re.compile(end_pat, re.M).search(text, m.end())
    if not e:
        sys.exit("prep_redact: cannot find end of %s" % what)
    end = e.end()
    if text[end:end + 1] == "\n":
        end += 1
    return text[:m.start()] + text[end:], text[m.start():end]


# 1. the redaction module moves as a file
subprocess.run(["git", "mv", os.path.join(RT, "agent/turn/redact.rs"), os.path.join(PV, "redact.rs")], check=True, cwd=repo)

# 2. approval::looks_like_secret_key
ap = read(os.path.join(RT, "approval/mod.rs"))
ap, secret_fn = cut(ap, r"^/// Heuristic for argument keys that should have their value redacted in\n", r"^}\n", "approval::looks_like_secret_key")
if "pub fn looks_like_secret_key" not in secret_fn:
    sys.exit("prep_redact: looks_like_secret_key block did not match")
m = re.search(r"(?m)^use ", ap)
ap = ap[:m.start()] + "pub use zeroclaw_providers::redact::looks_like_secret_key;\n" + ap[m.start():]
write(os.path.join(RT, "approval/mod.rs"), ap)

# 3. agent::loop_ export scrubbing
lp = read(os.path.join(RT, "agent/loop_.rs"))
lp, regex_static = cut(lp, r"^pub\(crate\) static IMAGE_DATA_URI_REGEX: LazyLock<Regex> = LazyLock::new\(\|\| \{\n", r"^\}\);\n", "IMAGE_DATA_URI_REGEX")
lp, elide_fn = cut(lp, r"^fn elide_image_data\(content: &str\) -> String \{\n", r"^}\n", "elide_image_data")
lp, scrub_fn = cut(lp, r"^pub\(crate\) fn scrub_for_export\(content: &str\) -> String \{\n", r"^}\n", "scrub_for_export")
reexport = "pub(crate) use zeroclaw_providers::redact::{IMAGE_DATA_URI_REGEX, scrub_for_export};\n"
if "use regex::Regex;\n" not in lp:
    sys.exit("prep_redact: agent/loop_.rs no longer has `use regex::Regex;`")
# The cut can leave `Regex` and `LazyLock` unused outside test code; keep `-D warnings` green.
body = lp.replace("use regex::Regex;\n", "", 1)
lp = lp.replace("use regex::Regex;\n", ("use regex::Regex;\n" if re.search(r"\bRegex\b", blank_tests(body)) else "") + reexport, 1)
if not re.search(r"\bLazyLock\b", blank_tests(lp.replace("use std::sync::{Arc, LazyLock, Mutex};", ""))):
    lp = lp.replace("use std::sync::{Arc, LazyLock, Mutex};", "#[cfg(test)]\nuse std::sync::LazyLock;\nuse std::sync::{Arc, Mutex};", 1)
write(os.path.join(RT, "agent/loop_.rs"), lp)

# 4. the moved file gains the three blocks; only what other crates use becomes `pub`
# (`elide_image_data` was private and stays private)
rd = read(os.path.join(PV, "redact.rs"))
rd = rd.replace("crate::approval::looks_like_secret_key(key)", "looks_like_secret_key(key)")
rd = rd.replace("pub(crate) static SENSITIVE_KV_REGEX", "pub static SENSITIVE_KV_REGEX").replace("pub(crate) static SENSITIVE_KEY_REGEX", "pub static SENSITIVE_KEY_REGEX")
block = "\n" + secret_fn + "\n" + regex_static.replace("pub(crate) static", "pub static") + "\n" + \
    elide_fn + "\n" + \
    scrub_fn.replace("pub(crate) fn", "pub fn").replace("zeroclaw_providers::scrub_secret_patterns", "crate::scrub_secret_patterns")
t = rd.find("#[cfg(test)]")
rd = (rd[:t].rstrip("\n") + "\n" + block + "\n" + rd[t:]) if t >= 0 else rd.rstrip("\n") + "\n" + block
write(os.path.join(PV, "redact.rs"), rd)

# 5. declarations and re-exports
pl = read(os.path.join(PV, "lib.rs"))
pl = pl.replace("mod request_payload;\n", "pub mod redact;\nmod request_payload;\n", 1)
write(os.path.join(PV, "lib.rs"), pl)
tm = read(os.path.join(RT, "agent/turn/mod.rs"))
if "pub(crate) mod redact;" not in tm:
    sys.exit("prep_redact: agent/turn/mod.rs no longer declares `pub(crate) mod redact;`")
tm = tm.replace("pub(crate) mod redact;", "pub(crate) use zeroclaw_providers::redact;", 1)
write(os.path.join(RT, "agent/turn/mod.rs"), tm)

# 6. the two modules that must stop naming the agent
for rel, old, new in [
    ("observability/otel.rs", "use crate::agent::loop_::scrub_for_export;", "use zeroclaw_providers::redact::scrub_for_export;"),
    ("hooks/builtin/webhook_audit.rs", "use crate::agent::loop_::scrub_for_export;", "use zeroclaw_providers::redact::scrub_for_export;"),
    ("hooks/builtin/webhook_audit.rs", "use crate::agent::turn::redact::scrub_credentials_value;", "use zeroclaw_providers::redact::scrub_credentials_value;"),
]:
    p = os.path.join(RT, rel)
    s = read(p)
    if old not in s:
        sys.exit("prep_redact: %s no longer has `%s`" % (rel, old))
    write(p, s.replace(old, new, 1))

print("prep_redact: done (redaction owned by zeroclaw-providers::redact; old paths re-exported)")
