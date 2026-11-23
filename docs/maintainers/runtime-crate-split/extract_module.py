#!/usr/bin/env python3
"""extract_module.py: regenerate a module-extraction change from scratch on any base.

Moves whole top-level modules out of a crate WITHOUT editing them (`git mv`, so the
moved files are 100% renames), and keeps every existing path valid:

  * the module keeps its name inside the destination crate
    (`zeroclaw_runtime::observability` -> `zeroclaw_observability::observability`),
    so `crate::observability::...` paths inside the moved files still resolve;
  * the source crate re-exports it (`pub use zeroclaw_observability::observability;`),
    so `crate::observability::...` in the source crate and
    `zeroclaw_runtime::observability::...` everywhere else still resolve;
  * references from the moved files to modules that already live in a lower crate
    are satisfied by crate-private aliases in the destination lib.rs
    (`--alias util=zeroclaw_infra::util`), again without touching the moved files.

Conditional compilation is carried over exactly or not at all. The cfg on the source
`mod` declaration goes onto the destination's, and each alias gets the cfg of the files
that use it. Where a gate cannot be read exactly (a multi-line attribute, `cfg_attr`,
`#[path]`, an inline module, or conditional code inside a file that uses an alias) the
script refuses and asks for the gate to be stated with `--alias name=target@<cfg>`.

The destination manifest is derived from what the moved files actually use: the
dependency lines and feature definitions are copied verbatim from the source
manifest, and the source crate's features are extended to forward to the new crate.

It refuses to move a file that reads a path relative to its crate at compile time
(`CARGO_MANIFEST_DIR`, `include_str!` and friends), and it registers a new crate in the
runtime's retained-dependency list, which a repository test enforces.

What it deliberately does NOT do: cut dependency back-edges (that is a separate,
reviewed prep change), widen `pub(crate)` items that the source crate still uses
(run widen_vis.py on `cargo check --message-format=json` output for that), or
update Cargo.lock (cargo does). It refuses to run if the moved files still
reference a module that would stay behind.

Usage:
  extract_module.py --repo . --modules observability \
      --new-crate zeroclaw-observability --description "..." \
      [--alias util=zeroclaw_infra::util] [--from-crate zeroclaw-runtime]
  extract_module.py --repo . --modules util --to-crate zeroclaw-infra
"""
import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from modgraph2 import blank, strip_tests, refs_in, modpath_of  # noqa: E402

DEP_SECTION = re.compile(r"^\[(?:target\..*\.)?(?:dev-|build-)?dependencies\]\s*$")
DEP_LINE = re.compile(r"^([A-Za-z0-9_-]+)(?:\.workspace)?\s*=")


def sh(repo, *a):
    subprocess.run(a, check=True, cwd=repo)


def read(p):
    return open(p, encoding="utf-8").read()


def write(p, s):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, "w", encoding="utf-8").write(s)


def sections(text):
    """Split a Cargo.toml into [(header or None, [lines])] preserving order."""
    out = [(None, [])]
    for line in text.split("\n"):
        if re.match(r"^\[.*\]\s*$", line):
            out.append((line.strip(), []))
        else:
            out[-1][1].append(line)
    return out


def join_sections(secs):
    parts = []
    for h, lines in secs:
        if h is not None:
            parts.append(h)
        parts.extend(lines)
    return "\n".join(parts)


def feature_defs(secs):
    """{name: (start_idx, end_idx, [items])} for the [features] section lines."""
    for h, lines in secs:
        if h == "[features]":
            defs = {}
            i = 0
            while i < len(lines):
                m = re.match(r"^([A-Za-z0-9_-]+)\s*=\s*\[", lines[i])
                if m:
                    j = i
                    buf = lines[i]
                    while "]" not in buf.split("=", 1)[1] and j + 1 < len(lines):
                        j += 1
                        buf += "\n" + lines[j]
                    items = re.findall(r'"([^"]+)"', buf.split("=", 1)[1])
                    defs[m.group(1)] = (i, j, items)
                    i = j + 1
                else:
                    i += 1
            return lines, defs
    return None, {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default=".")
    ap.add_argument("--from-crate", default="zeroclaw-runtime")
    ap.add_argument("--modules", required=True)
    ap.add_argument("--new-crate")
    ap.add_argument("--to-crate")
    ap.add_argument("--description", default="")
    ap.add_argument("--alias", action="append", default=[],
                    help="name=crate::path for a module that already lives lower; append @<cfg> (or @always) to "
                         "state the alias's gate when the script cannot infer it")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--retained-reason", default="",
                    help="why the source crate keeps depending on the new crate (>= 50 chars); written to the "
                         "retained-dependency list that tests/fixtures/runtime-composition-consumer enforces")
    a = ap.parse_args()

    repo = os.path.abspath(a.repo)
    mods = a.modules.split(",")
    dest = a.new_crate or a.to_crate
    if not dest:
        sys.exit("need --new-crate or --to-crate")
    dest_ident = dest.replace("-", "_")
    from_dir = os.path.join(repo, "crates", a.from_crate)
    from_src = os.path.join(from_dir, "src")
    dest_dir = os.path.join(repo, "crates", dest)
    dest_src = os.path.join(dest_dir, "src")
    # --alias name=target            the gate is inferred, or the script refuses and asks for one
    # --alias 'name=target@<cfg>'    the gate is stated: any cfg expression, or `always`
    aliases, alias_gate = {}, {}
    for x in a.alias:
        name, rest = x.split("=", 1)
        target, _, gate = rest.partition("@")
        aliases[name.strip()] = target.strip()
        if gate.strip():
            alias_gate[name.strip()] = gate.strip()

    # ---- 0. refuse if the moved files still reach for a module that stays behind
    top = set()
    for e in os.listdir(from_src):
        top.add(e[:-3] if e.endswith(".rs") else e)
    top.discard("lib")
    moved_rel = []
    for m in mods:
        p = os.path.join(from_src, m)
        if os.path.isdir(p):
            for d, _, fs in os.walk(p):
                moved_rel += [os.path.relpath(os.path.join(d, f), from_src) for f in fs if f.endswith(".rs")]
        if os.path.isfile(p + ".rs"):
            moved_rel.append(m + ".rs")
    if not moved_rel:
        sys.exit("nothing to move for %s" % mods)
    offenders = {}
    path_bound = []   # uses of the crate directory at compile time: these cannot move untouched
    per_file = []     # (rel, blanked text, production text)
    all_blank, prod_blank, raw_all = [], [], []
    for rel in sorted(moved_rel):
        raw = read(os.path.join(from_src, rel))
        b = blank(raw)
        prod, _, _ = strip_tests(raw, b)
        raw_all.append(raw)
        all_blank.append(b)
        prod_blank.append(prod)
        per_file.append((rel, b, prod))
        for pm in re.finditer(r"CARGO_MANIFEST_DIR|include_(?:str|bytes|dir)!\s*\(", b):
            path_bound.append("%s:%d" % (rel, b.count("\n", 0, pm.start()) + 1))
        for off, path in refs_in(b, modpath_of(rel)):
            if path and path[0] in top and path[0] not in mods and path[0] not in aliases:
                offenders.setdefault(path[0], []).append("%s:%d %s" % (rel, b.count("\n", 0, off) + 1, "::".join(path)))
    if offenders and not a.force:
        print("REFUSING: moved files reference modules that would stay in %s:" % a.from_crate)
        for k, v in sorted(offenders.items()):
            print("  %s (%d refs), e.g. %s" % (k, len(v), "; ".join(v[:3])))
        print("Cut these first (prep change), or pass --alias name=lower_crate::name if the module already lives lower.")
        sys.exit(2)
    if path_bound and not a.force:
        print("REFUSING: these lines resolve a path relative to the crate directory at compile time")
        print("(CARGO_MANIFEST_DIR or include_*!), so the file cannot move to another crate unedited:")
        print("  " + ", ".join(path_bound[:12]) + (" ..." if len(path_bound) > 12 else ""))
        print("Move the fixture or catalog with the module in a prep change, or pass --force and fix the paths by hand.")
        sys.exit(2)
    ALL, PROD, RAW = "\n".join(all_blank), "\n".join(prod_blank), "\n".join(raw_all)
    moved_lines = sum(r.count("\n") for r in raw_all)

    class Unsupported(Exception):
        pass

    def decl_cfgs(text, name, where):
        """The cfg expressions on the one `mod name;` declaration in `text`, or Unsupported.

        This reads only what it can read exactly: single-line attributes directly above a single
        declaration. Anything else (a multi-line attribute, `cfg_attr`, `#[path]`, an inline or
        duplicated declaration) raises, so the caller refuses to guess.
        """
        lines = text.split("\n")
        pat = re.compile(r"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?mod\s+%s\s*;" % re.escape(name))
        hits = [k for k, line in enumerate(lines) if pat.match(line)]
        if len(hits) != 1:
            raise Unsupported("%s: expected one `mod %s;` declaration, found %d (inline module, #[path] under "
                              "another name, or one declaration per cfg)" % (where, name, len(hits)))
        cfgs, k = [], hits[0] - 1
        while k >= 0:
            line = lines[k].strip()
            if line.startswith("//"):
                k -= 1
                continue
            if not line.startswith("#["):
                if line.endswith("]"):
                    raise Unsupported("%s: a multi-line attribute sits above `mod %s;`" % (where, name))
                break
            if not line.endswith("]"):
                raise Unsupported("%s: a multi-line attribute sits above `mod %s;`" % (where, name))
            if re.match(r"#\[\s*(cfg_attr|path)\b", line):
                raise Unsupported("%s: `mod %s;` carries %s" % (where, name, line))
            cm = re.match(r"#\[\s*cfg\s*\((.*)\)\s*\]$", line)
            if cm:
                cfgs.append(cm.group(1).strip())
            k -= 1
        return cfgs

    def mod_gates(rel):
        """Every cfg on the `mod` declarations from the crate root down to this file; all must hold."""
        gates = []
        parts = modpath_of(rel)
        for depth in range(len(parts), 0, -1):
            name, parent = parts[depth - 1], parts[:depth - 1]
            cands = [os.path.join(from_src, "lib.rs")] if not parent else [
                os.path.join(from_src, *parent, "mod.rs"), os.path.join(from_src, *parent) + ".rs"]
            found = [c for c in cands if os.path.isfile(c)]
            if not found:
                raise Unsupported("%s: no file declares module `%s`" % (rel, "::".join(parts[:depth])))
            gates += decl_cfgs(read(found[0]), name, os.path.relpath(found[0], from_src))
        return gates

    FINE_CFG = re.compile(r"#\s*\[\s*cfg(?:_attr)?\s*\(|\bcfg!\s*\(")
    TEST_CFG = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")

    def alias_cfg(name):
        """The cfg an alias needs so that it is declared exactly when some file uses it.

        A file's uses are live when every gate above it holds, so each file contributes the
        conjunction of its gates (plus `test` if only its test code uses the alias). The alias
        is needed when any file's conjunction holds. A file that has conditional compilation
        inside it, other than plain `#[cfg(test)]`, could use the alias under a finer condition
        than its module gate; that is not inferred, it is refused.
        """
        preds = set()
        for rel, b, prod in per_file:
            mp = modpath_of(rel)
            if not any(pth and pth[0] == name for _, pth in refs_in(b, mp)):
                continue
            if len(FINE_CFG.findall(b)) > len(TEST_CFG.findall(b)):
                raise Unsupported("%s uses `crate::%s` and has conditional compilation inside the file" % (rel, name))
            atoms = set(mod_gates(rel))
            if not any(pth and pth[0] == name for _, pth in refs_in(prod, mp)):
                atoms.add("test")
            preds.add(frozenset(atoms))
        if not preds or frozenset() in preds:
            return ""
        preds = [q for q in preds if not any(o < q for o in preds)]   # a weaker condition covers a stronger one

        def conj(q):
            q = sorted(q, key=lambda x: (x != "test", x))
            return q[0] if len(q) == 1 else "all(%s)" % ", ".join(q)
        terms = sorted(conj(q) for q in preds)
        return "#[cfg(%s)]\n" % (terms[0] if len(terms) == 1 else "any(%s)" % ", ".join(terms))

    # Work every gate out now: they are read from the module tree, which step 1 is about to move.
    # Either each gate is read exactly, or nothing is moved.
    refusals, alias_attr, top_gate = [], {}, {}
    lib_text = read(os.path.join(from_src, "lib.rs"))
    for m in mods:
        try:
            top_gate[m] = decl_cfgs(lib_text, m, "lib.rs")
        except Unsupported as e:
            refusals.append(str(e))
    for n in sorted(aliases):
        if n in alias_gate:
            alias_attr[n] = "" if alias_gate[n] == "always" else "#[cfg(%s)]\n" % alias_gate[n]
            continue
        try:
            alias_attr[n] = alias_cfg(n)
        except Unsupported as e:
            refusals.append("%s. State the gate yourself: --alias '%s=%s@<cfg expression>' (or @always)."
                            % (e, n, aliases[n]))
    if refusals:
        print("REFUSING: a cfg gate could not be read exactly, and this script does not guess:")
        for r in refusals:
            print("  " + r)
        sys.exit(2)
    gate_text = "\n".join(g for gs in top_gate.values() for g in gs) + "\n" + "\n".join(alias_gate.values())

    def mod_decl(m):
        """`pub mod m;` for the destination, under the same cfg the source declaration carried."""
        return "".join("#[cfg(%s)]\n" % g for g in top_gate[m]) + "pub mod %s;\n" % m

    # ---- 1. move, byte for byte
    os.makedirs(dest_src, exist_ok=True)
    for m in mods:
        for suffix in ("", ".rs"):
            p = os.path.join(from_src, m + suffix)
            if os.path.exists(p):
                sh(repo, "git", "mv", p, os.path.join(dest_src, m + suffix))

    # ---- 2. dependencies the moved files use (lines copied verbatim from the source manifest)
    fman = read(os.path.join(from_dir, "Cargo.toml"))
    fsecs = sections(fman)

    def used(ident, text):
        return re.search(r"(?<![A-Za-z0-9_])%s\s*::" % re.escape(ident), text) or \
            re.search(r"\buse\s+%s\s*(;|as\b)" % re.escape(ident), text)

    want = {}   # dest section header -> [lines]
    copied = set()
    for h, lines in fsecs:
        if not h or not DEP_SECTION.match(h):
            continue
        is_dev = "dev-dependencies" in h
        for line in lines:
            m = DEP_LINE.match(line)
            if not m:
                continue
            name = m.group(1)
            ident = name.replace("-", "_")
            if name == dest:
                continue
            if is_dev:
                if used(ident, ALL):
                    want.setdefault(h, []).append(line)
                    copied.add(name)
            elif used(ident, PROD):
                want.setdefault(h, []).append(line)
                copied.add(name)
            elif used(ident, ALL):
                want.setdefault(h.replace("dependencies]", "dependencies]").replace("[dependencies]", "[dev-dependencies]")
                                if h == "[dependencies]" else h.replace(".dependencies]", ".dev-dependencies]"), []).append(line)
                copied.add(name)
    for target in aliases.values():
        dep = target.split("::")[0].replace("_", "-")
        if dep not in copied:
            want.setdefault("[dependencies]", []).append("%s.workspace = true" % dep)
            copied.add(dep)

    # ---- 3. features named in the moved files
    flines, fdefs = feature_defs(fsecs)
    feat_used = sorted(set(re.findall(r'feature\s*=\s*"([^"]+)"', RAW + "\n" + gate_text)) & set(fdefs))
    dest_feats = {}
    for f in feat_used:
        keep = []
        for it in fdefs[f][2]:
            if it.startswith("dep:"):
                if it[4:] in copied:
                    keep.append(it)
            elif "/" in it:
                if it.split("/")[0].rstrip("?") in copied:
                    keep.append(it)
            elif it in feat_used:
                keep.append(it)
        dest_feats[f] = keep

    # ---- 4. destination manifest + lib.rs
    dman_path = os.path.join(dest_dir, "Cargo.toml")
    if a.new_crate:
        order = sorted(want, key=lambda h: (h != "[dependencies]", "dev-" in h, h))
        body = ['[package]', 'name = "%s"' % dest, 'version.workspace = true', 'edition.workspace = true',
                'license.workspace = true', 'description = "%s"' % a.description.replace('"', "'"),
                'repository.workspace = true', 'homepage.workspace = true', 'publish = true', '']
        for h in order:
            if "dev-" in h:
                continue
            body += [h] + want[h] + [""]
        if dest_feats:
            body += ["[features]"] + ['%s = [%s]' % (f, ", ".join('"%s"' % x for x in v)) for f, v in dest_feats.items()] + [""]
        for h in order:
            if "dev-" in h:
                body += [h] + want[h] + [""]
        for h, lines in fsecs:
            if h and h.startswith("[lints") and any(c in RAW for c in re.findall(r"cfg\(([a-z_]+)\)", "\n".join(lines))):
                body += [h] + [x for x in lines if x.strip()] + [""]
        write(dman_path, "\n".join(body))
        inner = re.findall(r"(?ms)^#!\[allow\(.*?\)\]\n", read(os.path.join(from_src, "lib.rs")))
        lib = "".join(inner)
        lib += "//! %s\n//!\n" % (a.description or dest)
        lib += "//! Extracted from `%s`. Each module keeps its original name here, and\n" % a.from_crate
        lib += "//! `%s` re-exports it, so existing `%s::<module>` paths are unchanged.\n\n" % (a.from_crate, a.from_crate.replace("-", "_"))
        lib += "".join(mod_decl(m) for m in mods)
        if aliases:
            lib += "\n// The moved files keep their original `crate::<module>` paths; these aliases point\n"
            lib += "// them at the crate that owns that module now.\n"
            lib += "// Each alias carries the same feature gate as the files that use it.\n"
            lib += "".join("%spub(crate) use %s;\n" % (alias_attr[n], t) for n, t in sorted(aliases.items()))
        write(os.path.join(dest_src, "lib.rs"), lib)
    else:
        dsecs = sections(read(dman_path))
        heads = [h for h, _ in dsecs]
        for h, lines in want.items():
            if h in heads:
                sec = dsecs[heads.index(h)][1]
                have = {DEP_LINE.match(x).group(1) for x in sec if DEP_LINE.match(x)}
                add = [x for x in lines if DEP_LINE.match(x).group(1) not in have]
                k = len(sec)
                while k > 0 and not sec[k - 1].strip():
                    k -= 1
                sec[k:k] = add
            else:
                # A new section goes before [dev-dependencies], not at the end of the file: the end of a
                # manifest is where other pull requests append, and two appends at one spot conflict.
                # Measured on the util move: end-of-file broke 5 open pull requests, this placement 1.
                at = next((i for i, x in enumerate(heads) if x and "dev-dependencies" in x), len(dsecs))
                dsecs.insert(at, (h, lines + [""]))
                heads.insert(at, h)
        write(dman_path, join_sections(dsecs))
        lp = os.path.join(dest_src, "lib.rs")
        lib = read(lp).rstrip("\n") + "\n" + "".join(mod_decl(m) for m in mods)
        write(lp, lib)

    # ---- 5. source crate: re-export instead of declare, depend on dest, forward features
    lp = os.path.join(from_src, "lib.rs")
    lib = read(lp)
    for m in mods:
        pat = re.compile(r"(?m)^(\s*)(pub(?:\([^)]*\))?\s+)?mod\s+%s\s*;" % re.escape(m))
        mm = pat.search(lib)
        if not mm:
            sys.exit("no `mod %s;` in %s" % (m, lp))
        vis = "pub " if (mm.group(2) or "").strip() == "pub" else "pub(crate) "
        lib = lib[:mm.start()] + "%s%suse %s::%s;" % (mm.group(1), vis, dest_ident, m) + lib[mm.end():]
    write(lp, lib)

    fsecs = sections(read(os.path.join(from_dir, "Cargo.toml")))
    for h, lines in fsecs:
        if h == "[dependencies]" and not any(DEP_LINE.match(x) and DEP_LINE.match(x).group(1) == dest for x in lines):
            k = max(i for i, x in enumerate(lines) if x.startswith("zeroclaw-"))
            lines.insert(k + 1, "%s.workspace = true" % dest)
        if h == "[features]":
            _, defs = feature_defs(fsecs)
            for f in sorted(dest_feats, key=lambda f: -defs[f][0]):
                i, j, items = defs[f]
                fwd = '"%s/%s"' % (dest, f)
                if fwd.strip('"') in items:
                    continue
                if i == j:
                    head, rest = lines[i].split("[", 1)
                    inner, tail = rest.rsplit("]", 1)
                    inner = inner.strip()
                    lines[i] = "%s[%s%s]%s" % (head, (inner.rstrip(",") + ", ") if inner else "", fwd, tail)
                else:
                    lines.insert(j, "    %s," % fwd)
    write(os.path.join(from_dir, "Cargo.toml"), join_sections(fsecs))

    # ---- 6. workspace registration (new crates only)
    if a.new_crate:
        wp = os.path.join(repo, "Cargo.toml")
        w = read(wp)
        anchor = '"crates/%s"' % a.from_crate
        if '"crates/%s"' % dest not in w:
            w = w.replace(anchor, '"crates/%s", %s' % (dest, anchor), 1)
        m = re.search(r'(?m)^%s = \{ path = "crates/%s", version = "([^"]+)".*$' % (re.escape(a.from_crate), re.escape(a.from_crate)), w)
        if m and not re.search(r"(?m)^%s = " % re.escape(dest), w):
            w = w[:m.start()] + '%s = { path = "crates/%s", version = "%s" }\n' % (dest, dest, m.group(1)) + w[m.start():]
        write(wp, w)

    # ---- 7. the retained-dependency list a repository test enforces for the runtime crate
    retained = os.path.join(repo, "tests/fixtures/runtime-composition-consumer/retained-dependencies.json")
    registered = ""
    if a.new_crate and a.from_crate == "zeroclaw-runtime" and os.path.isfile(retained):
        reason = a.retained_reason or (
            "%s Extracted from zeroclaw-runtime, which re-exports the module so existing paths keep resolving."
            % a.description).strip()
        if len(reason.encode("utf-8")) < 50:
            sys.exit("--retained-reason must be at least 50 characters (the repository test enforces it)")
        t = read(retained)
        if '"%s"' % dest not in t:
            keys = list(re.finditer(r'(?m)^    "(zeroclaw-[a-z-]+)": \{\n', t))
            if not keys:
                sys.exit("cannot find an entry to anchor on in %s" % retained)
            entry = '    "%s": {\n      "owner": "crates/%s/src/lib.rs",\n      "reason": %s\n    },\n' % (
                dest, a.from_crate, json.dumps(reason))
            at = keys[-1].start()     # before the last entry: not at the end, where other changes append
            write(retained, t[:at] + entry + t[at:])
            registered = "  retained-dependency entry added for %s" % dest

    print("moved %d files (%d lines) from %s to %s, unedited" % (len(moved_rel), moved_lines, a.from_crate, dest))
    if registered:
        print(registered)
    for h in sorted(want):
        print("  %s: %s" % (h, ", ".join(DEP_LINE.match(x).group(1) for x in want[h])))
    if dest_feats:
        print("  features forwarded: %s" % ", ".join(dest_feats))
    if aliases:
        print("  aliases: %s" % ", ".join("%s -> %s%s" % (n, t, (" [%s]" % alias_attr[n].strip()) if alias_attr[n] else "")
                                         for n, t in sorted(aliases.items())))
    print("next: cargo check --message-format=json | widen_vis.py ; then the registration checklist in PLAN.md")


if __name__ == "__main__":
    main()
