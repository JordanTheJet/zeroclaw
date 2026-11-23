#!/usr/bin/env python3
"""test_extract_module.py: fixture tests for extract_module.py. Needs python3 and git, no cargo.

    python3 test_extract_module.py

Each case builds a small throwaway workspace under the system temp directory, runs the real
script on it, and checks exactly what it wrote. The cases cover what four reviews found wrong
or untested: the cfg gate on a generated alias, the gate on the moved module itself, the
refusals, the manifests, `--to-crate`, and the retained-dependency entry.
"""
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "extract_module.py")
RT = "crates/zeroclaw-runtime/"

ROOT_TOML = '''[workspace]
members = [".", "crates/zeroclaw-low", "crates/zeroclaw-runtime"]
resolver = "2"

[workspace.dependencies]
zeroclaw-low = { path = "crates/zeroclaw-low", version = "0.1.0" }
zeroclaw-runtime = { path = "crates/zeroclaw-runtime", version = "0.1.0", default-features = false }
'''
RUNTIME_TOML = '''[package]
name = "zeroclaw-runtime"
version = "0.1.0"

[dependencies]
zeroclaw-low.workspace = true
serde_json = "1"

[features]
outer = []
inner = []
'''
RETAINED = '''{
  "issue": "#1",
  "normal": {
    "zeroclaw-low": {
      "owner": "crates/zeroclaw-runtime/src/lib.rs",
      "reason": "Lower helpers the runtime has always used; kept as an explained edge for this fixture."
    },
    "zeroclaw-last": {
      "owner": "crates/zeroclaw-runtime/src/lib.rs",
      "reason": "A second entry, so the new one has something to be inserted in front of in this test."
    }
  },
  "build": {}
}
'''


def build(files, lib="pub use zeroclaw_low::util;\npub mod agentish;\npub mod m;\n"):
    """Create a committed git repo with the base fixture plus `files` ({relative path: text})."""
    d = tempfile.mkdtemp(prefix="extract-test-")
    base = {
        "Cargo.toml": ROOT_TOML,
        "crates/zeroclaw-low/Cargo.toml": '[package]\nname = "zeroclaw-low"\nversion = "0.1.0"\n',
        "crates/zeroclaw-low/src/lib.rs": "pub mod util;\n",
        "crates/zeroclaw-low/src/util.rs": "pub fn helper() {}\n",
        RT + "Cargo.toml": RUNTIME_TOML,
        RT + "src/lib.rs": lib,
        RT + "src/agentish.rs": "pub fn run() {}\n",
    }
    base.update(files)
    for rel, text in base.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(text)
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@localhost", "-c", "init.defaultBranch=main"]
    for a in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "fixture"]):
        subprocess.run(git + a, cwd=d, check=True)
    return d


def extract(d, alias="util=zeroclaw_low::util", dest=("--new-crate", "zeroclaw-m")):
    args = [sys.executable, SCRIPT, "--repo", d, "--modules", "m", "--description", "fixture"] + list(dest)
    if alias:
        args += ["--alias", alias]
    r = subprocess.run(args, capture_output=True, text=True)
    lib = os.path.join(d, "crates/zeroclaw-m/src/lib.rs")
    return r, (open(lib).read() if os.path.isfile(lib) else "")


def rd(d, rel):
    return open(os.path.join(d, rel)).read()


def code_lines(lib):
    """lib.rs without comments and blank lines: the declarations and their attributes, in order."""
    return [x for x in lib.split("\n") if x.strip() and not x.startswith("//")]


def nothing_moved(d, lib):
    st = subprocess.run(["git", "status", "--porcelain"], cwd=d, capture_output=True, text=True).stdout
    return st == "" and not lib and os.path.isdir(os.path.join(d, RT + "src/m"))


USES = "use crate::util::helper;\npub fn f() { helper(); }\n"
TEST_ONLY = "pub fn g() {}\n\n#[cfg(test)]\nmod tests {\n    use crate::util::helper;\n    #[test]\n    fn t() { helper(); }\n}\n"
ALIAS = "pub(crate) use zeroclaw_low::util;"
CASES = []


def case(fn):
    CASES.append(fn)
    return fn


def ok(r):
    assert r.returncode == 0, r.stdout + r.stderr


def refused(r, needle):
    assert r.returncode == 2 and "REFUSING" in r.stdout and needle in r.stdout, "rc=%d\n%s%s" % (r.returncode, r.stdout, r.stderr)


# ---- the gate on a generated alias -------------------------------------------------------

@case
def ungated_use_gets_no_gate():
    d = build({RT + "src/m/mod.rs": "pub mod a;\n", RT + "src/m/a.rs": USES})
    r, lib = extract(d); ok(r)
    assert code_lines(lib) == ["pub mod m;", ALIAS], lib


@case
def one_gate():
    d = build({RT + "src/m/mod.rs": '#[cfg(feature = "outer")]\npub mod a;\n', RT + "src/m/a.rs": USES})
    r, lib = extract(d); ok(r)
    assert code_lines(lib) == ["pub mod m;", '#[cfg(feature = "outer")]', ALIAS], lib


@case
def nested_gates_are_both_required():
    # The third review's counter-example: parent gated on `outer`, child on `inner`, the only
    # use in the child. An earlier version emitted cfg(inner) alone.
    d = build({RT + "src/m/mod.rs": '#[cfg(feature = "outer")]\npub mod a;\n',
               RT + "src/m/a/mod.rs": '#[cfg(feature = "inner")]\nmod b;\n',
               RT + "src/m/a/b.rs": USES})
    r, lib = extract(d); ok(r)
    assert code_lines(lib) == ["pub mod m;", '#[cfg(all(feature = "inner", feature = "outer"))]', ALIAS], lib


@case
def two_attributes_on_one_declaration():
    d = build({RT + "src/m/mod.rs": '#[cfg(feature = "outer")]\n#[cfg(feature = "inner")]\npub mod a;\n',
               RT + "src/m/a.rs": USES})
    r, lib = extract(d); ok(r)
    assert code_lines(lib) == ["pub mod m;", '#[cfg(all(feature = "inner", feature = "outer"))]', ALIAS], lib


@case
def test_only_use_is_gated_on_test():
    d = build({RT + "src/m/mod.rs": "pub mod a;\n", RT + "src/m/a.rs": TEST_ONLY})
    r, lib = extract(d); ok(r)
    assert code_lines(lib) == ["pub mod m;", "#[cfg(test)]", ALIAS], lib


@case
def gated_use_or_test_use():
    d = build({RT + "src/m/mod.rs": '#[cfg(feature = "outer")]\npub mod a;\npub mod c;\n',
               RT + "src/m/a.rs": USES, RT + "src/m/c.rs": TEST_ONLY})
    r, lib = extract(d); ok(r)
    assert code_lines(lib) == ["pub mod m;", '#[cfg(any(feature = "outer", test))]', ALIAS], lib


@case
def a_non_feature_gate_is_carried_too():
    d = build({RT + "src/m/mod.rs": "#[cfg(unix)]\n#[allow(dead_code)]\npub mod a;\n", RT + "src/m/a.rs": USES})
    r, lib = extract(d); ok(r)
    assert code_lines(lib) == ["pub mod m;", "#[cfg(unix)]", ALIAS], lib


# ---- gates the script cannot read exactly: it refuses, and moves nothing ------------------

@case
def refuses_a_multi_line_cfg():
    d = build({RT + "src/m/mod.rs": '#[cfg(all(\n    feature = "outer",\n    feature = "inner"\n))]\npub mod a;\n',
               RT + "src/m/a.rs": USES})
    r, lib = extract(d); refused(r, "multi-line attribute")
    assert nothing_moved(d, lib)


@case
def refuses_cfg_attr():
    d = build({RT + "src/m/mod.rs": '#[cfg_attr(feature = "outer", allow(dead_code))]\npub mod a;\n',
               RT + "src/m/a.rs": USES})
    r, lib = extract(d); refused(r, "cfg_attr")
    assert nothing_moved(d, lib)


@case
def refuses_a_path_attribute():
    d = build({RT + "src/m/mod.rs": '#[cfg(feature = "outer")]\n#[path = "a.rs"]\npub mod a;\n',
               RT + "src/m/a.rs": USES})
    r, lib = extract(d); refused(r, "#[path")
    assert nothing_moved(d, lib)


@case
def refuses_a_use_under_a_cfg_inside_the_file():
    d = build({RT + "src/m/mod.rs": "pub mod a;\n",
               RT + "src/m/a.rs": '#[cfg(feature = "inner")]\npub fn f() { crate::util::helper(); }\n'})
    r, lib = extract(d); refused(r, "conditional compilation inside the file")
    assert "--alias 'util=zeroclaw_low::util@<cfg expression>'" in r.stdout, r.stdout
    assert nothing_moved(d, lib)


@case
def refuses_a_use_in_a_gated_inline_module():
    d = build({RT + "src/m/mod.rs": "pub mod a;\n",
               RT + "src/m/a.rs": '#[cfg(feature = "inner")]\nmod inner {\n    pub fn f() { crate::util::helper(); }\n}\n'})
    r, lib = extract(d); refused(r, "conditional compilation inside the file")
    assert nothing_moved(d, lib)


@case
def refuses_a_gate_on_the_moved_module_it_cannot_read():
    d = build({RT + "src/m/mod.rs": "pub mod a;\n", RT + "src/m/a.rs": "pub fn f() {}\n"},
              lib='pub use zeroclaw_low::util;\npub mod agentish;\n#[cfg_attr(feature = "outer", allow(dead_code))]\npub mod m;\n')
    r, lib = extract(d, alias=None); refused(r, "lib.rs")
    assert nothing_moved(d, lib)


@case
def a_stated_gate_is_used_as_given():
    files = {RT + "src/m/mod.rs": "pub mod a;\n",
             RT + "src/m/a.rs": '#[cfg(feature = "inner")]\npub fn f() { crate::util::helper(); }\n'}
    r, lib = extract(build(files), alias='util=zeroclaw_low::util@feature = "inner"'); ok(r)
    assert code_lines(lib) == ["pub mod m;", '#[cfg(feature = "inner")]', ALIAS], lib
    r, lib = extract(build(files), alias="util=zeroclaw_low::util@always"); ok(r)
    assert code_lines(lib) == ["pub mod m;", ALIAS], lib


# ---- the gate on the moved module itself ---------------------------------------------------

@case
def the_source_gate_goes_onto_the_destination_module():
    # The fourth review: a gate on `mod m;` in the source lib.rs must not become an
    # unconditional `pub mod m;`, and a feature named only there must still be declared
    # in the new crate and forwarded from the old one.
    d = build({RT + "src/m/mod.rs": "pub mod a;\n", RT + "src/m/a.rs": "pub fn f() {}\n"},
              lib='pub use zeroclaw_low::util;\npub mod agentish;\n#[cfg(feature = "outer")]\npub mod m;\n')
    r, lib = extract(d, alias=None); ok(r)
    assert code_lines(lib) == ['#[cfg(feature = "outer")]', "pub mod m;"], lib
    assert '#[cfg(feature = "outer")]\npub use zeroclaw_m::m;\n' in rd(d, RT + "src/lib.rs")
    assert re.search(r"(?m)^outer = \[\]$", rd(d, "crates/zeroclaw-m/Cargo.toml"))
    assert re.search(r'(?m)^outer = \["zeroclaw-m/outer"\]$', rd(d, RT + "Cargo.toml"))
    assert not re.search(r"(?m)^inner", rd(d, "crates/zeroclaw-m/Cargo.toml"))


# ---- what a move writes ---------------------------------------------------------------------

@case
def the_move_itself():
    d = build({RT + "src/m/mod.rs": '#[cfg(feature = "outer")]\npub mod a;\n', RT + "src/m/a.rs": USES})
    r, lib = extract(d); ok(r)
    assert rd(d, RT + "src/lib.rs") == "pub use zeroclaw_low::util;\npub mod agentish;\npub use zeroclaw_m::m;\n"
    assert not os.path.exists(os.path.join(d, RT + "src/m"))
    assert rd(d, "crates/zeroclaw-m/src/m/a.rs") == USES                       # byte for byte
    rt = rd(d, RT + "Cargo.toml")
    assert rt == RUNTIME_TOML.replace("zeroclaw-low.workspace = true\n", "zeroclaw-low.workspace = true\nzeroclaw-m.workspace = true\n") \
                             .replace("outer = []", 'outer = ["zeroclaw-m/outer"]'), rt
    new = rd(d, "crates/zeroclaw-m/Cargo.toml")
    assert re.search(r'(?m)^name = "zeroclaw-m"$', new) and re.search(r"(?m)^publish = true$", new), new
    deps = new.split("[dependencies]\n")[1].split("\n\n")[0].split("\n")
    assert deps == ["zeroclaw-low.workspace = true"], new                      # serde_json is unused, so absent
    assert new.split("[features]\n")[1].strip().split("\n") == ["outer = []"], new
    root = rd(d, "Cargo.toml")
    assert 'members = [".", "crates/zeroclaw-low", "crates/zeroclaw-m", "crates/zeroclaw-runtime"]' in root, root
    assert re.search(r'(?m)^zeroclaw-m = \{ path = "crates/zeroclaw-m", version = "0\.1\.0" \}$', root), root
    st = subprocess.run(["git", "status", "--porcelain"], cwd=d, capture_output=True, text=True).stdout
    assert "R  crates/zeroclaw-runtime/src/m/a.rs -> crates/zeroclaw-m/src/m/a.rs" in st, st
    assert "R  crates/zeroclaw-runtime/src/m/mod.rs -> crates/zeroclaw-m/src/m/mod.rs" in st, st


@case
def moving_into_an_existing_crate():
    d = build({RT + "src/m/mod.rs": "pub mod a;\n", RT + "src/m/a.rs": "pub fn f() {}\n"},
              lib='pub use zeroclaw_low::util;\npub mod agentish;\n#[cfg(feature = "outer")]\npub mod m;\n')
    r, _ = extract(d, alias=None, dest=("--to-crate", "zeroclaw-low")); ok(r)
    assert rd(d, "crates/zeroclaw-low/src/lib.rs") == 'pub mod util;\n#[cfg(feature = "outer")]\npub mod m;\n'
    assert '#[cfg(feature = "outer")]\npub use zeroclaw_low::m;\n' in rd(d, RT + "src/lib.rs")
    assert rd(d, "crates/zeroclaw-low/src/m/a.rs") == "pub fn f() {}\n"
    assert rd(d, "Cargo.toml") == ROOT_TOML                                    # no new workspace member
    assert not os.path.exists(os.path.join(d, "crates/zeroclaw-m"))


@case
def the_retained_dependency_entry():
    rel = "tests/fixtures/runtime-composition-consumer/retained-dependencies.json"
    d = build({RT + "src/m/mod.rs": "pub mod a;\n", RT + "src/m/a.rs": "pub fn f() {}\n", rel: RETAINED})
    r, _ = extract(d, alias=None); ok(r)
    policy = json.loads(rd(d, rel))
    assert list(policy["normal"]) == ["zeroclaw-low", "zeroclaw-m", "zeroclaw-last"], list(policy["normal"])
    entry = policy["normal"]["zeroclaw-m"]
    assert entry["owner"] == "crates/zeroclaw-runtime/src/lib.rs" and os.path.isfile(os.path.join(d, entry["owner"]))
    assert len(entry["reason"].encode("utf-8")) >= 50, entry
    before, after = RETAINED.split('    "zeroclaw-last"')                       # everything else untouched
    assert rd(d, rel).startswith(before) and rd(d, rel).endswith('    "zeroclaw-last"' + after)


# ---- refusals that protect the layering -----------------------------------------------------

@case
def refuses_an_upward_reference():
    d = build({RT + "src/m/mod.rs": "pub mod a;\n", RT + "src/m/a.rs": "pub fn f() { crate::agentish::run(); }\n"})
    r, lib = extract(d); refused(r, "agentish")
    assert nothing_moved(d, lib)


@case
def refuses_a_crate_relative_path():
    d = build({RT + "src/m/mod.rs": "pub mod a;\n",
               RT + "src/m/a.rs": 'pub const T: &str = include_str!("../../fixture.txt");\n'})
    r, lib = extract(d); refused(r, "m/a.rs:1")
    assert nothing_moved(d, lib)


def main():
    failed = 0
    for fn in CASES:
        try:
            fn()
            print("ok    %s" % fn.__name__)
        except AssertionError as e:
            failed += 1
            print("FAIL  %s\n%s" % (fn.__name__, str(e)[:1500]))
    print("%d cases, %d failed" % (len(CASES), failed))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
