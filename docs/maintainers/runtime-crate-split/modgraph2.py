#!/usr/bin/env python3
"""modgraph2.py: module-level dependency graph of one Rust crate's src tree.

A stricter replacement for modgraph.py / fas.py. Still syntactic (no compiler),
but it fixes the known misses of the regex version:

  * comments (incl. doc comments) and string literals are blanked before matching;
  * every `#[cfg(test)]` item is removed by brace matching, wherever it sits
    (not "everything after the first test module"), and files declared through
    `#[cfg(test)] mod x;` are treated as test files;
  * grouped imports are expanded: `use crate::{agent::x, tools::{a, b}}`;
  * `super::` chains are resolved against the file's module path;
  * `crate::Name` that is a `pub use` re-export in lib.rs is mapped to its module;
  * a reference that only passes through a re-export of ANOTHER crate
    (`crate::tools::Tool` where tools/mod.rs has `pub use zeroclaw_api::tool::Tool`)
    is classified "passthrough", because it is not a dependency on that module's code.

Usage:
  modgraph2.py <crate-src-dir> [--json out.json] [--depth2 agent,tools,...]
               [--ext <dir> ...]   # other source trees to scan for `<crate_ident>::` uses
               [--crate-ident zeroclaw_runtime]

Limits (be honest about them): feature-gated code is counted whatever the feature;
a glob re-export of another crate is recognised only when the module does not define
the name itself; glob imports
(`use crate::x::*`) count as one reference; a method call on a value whose type is
never named is invisible (the type's owner is still reached transitively through
whatever function produced the value). The compiler is the final arbiter: a move
is proven by `cargo check`, not by this script.
"""
import collections
import json
import os
import re
import sys

IDENT = re.compile(r'(?:r#)?[A-Za-z_][A-Za-z0-9_]*')


def blank(src):
    """Return src with comments and string/char literal contents replaced by spaces."""
    out = list(src)
    n = len(src)
    i = 0

    def fill(a, b):
        for k in range(a, b):
            if out[k] != '\n':
                out[k] = ' '

    while i < n:
        c = src[i]
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            j = src.find('\n', i)
            j = n if j < 0 else j
            fill(i, j)
            i = j
        elif c == '/' and i + 1 < n and src[i + 1] == '*':
            depth, j = 1, i + 2
            while j < n and depth:
                if src.startswith('/*', j):
                    depth += 1; j += 2
                elif src.startswith('*/', j):
                    depth -= 1; j += 2
                else:
                    j += 1
            fill(i, j)
            i = j
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == '\\' else 1
            fill(i + 1, min(j, n))
            i = j + 1
        elif c == 'r' and i + 1 < n and src[i + 1] in '#"' and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == '_')):
            j = i + 1
            hashes = 0
            while j < n and src[j] == '#':
                hashes += 1; j += 1
            if j < n and src[j] == '"':
                end = src.find('"' + '#' * hashes, j + 1)
                end = n if end < 0 else end
                fill(j + 1, end)
                i = end + 1 + hashes
            else:
                i += 1  # r#ident
        elif c == "'":
            if i + 1 < n and src[i + 1] == '\\':
                j = src.find("'", i + 2)
                j = n if j < 0 else j
                fill(i + 1, j)
                i = j + 1
            elif i + 2 < n and src[i + 2] == "'":
                fill(i + 1, i + 2)
                i += 3
            else:
                i += 1  # lifetime
        else:
            i += 1
    return ''.join(out)


def match_close(text, i, open_ch, close_ch):
    """i is the index of open_ch; return index just past the matching close."""
    depth = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


ATTR = re.compile(r'#\s*\[')
TEST_FEATURES = ('test-util', 'test-helpers', 'testing')


def is_test_attr(raw_attr, blank_attr):
    body = blank_attr.strip()
    m = re.match(r'#\s*\[\s*cfg\s*\(', body)
    if m:
        inner = body[m.end():]
        inner = re.sub(r'not\s*\([^()]*\)', ' ', inner)
        if re.search(r'\btest\b', inner):
            return True
        if any(('"%s"' % f) in raw_attr for f in TEST_FEATURES) and 'not(' not in raw_attr:
            return True
        return False
    if re.match(r'#\s*\[\s*(?:tokio\s*::\s*)?test\b', body):
        return True
    return False


def strip_tests(raw, text):
    """Blank every test-only item in `text` (already comment/string-blanked).

    Returns (text, removed_line_count, test_child_mods).
    """
    out = list(text)
    n = len(text)
    removed = []
    test_mods = []
    pos = 0
    while True:
        m = ATTR.search(text, pos)
        if not m:
            break
        a0 = m.start()
        a1 = match_close(text, text.index('[', a0), '[', ']')
        if not is_test_attr(raw[a0:a1], text[a0:a1]):
            pos = a1
            continue
        # skip further attributes
        j = a1
        while True:
            k = j
            while k < n and text[k].isspace():
                k += 1
            if text.startswith('#', k) and ATTR.match(text, k):
                j = match_close(text, text.index('[', k), '[', ']')
            else:
                j = k
                break
        # find end of item: first ';' or '{' at paren/bracket depth 0
        depth = 0
        k = j
        end = n
        while k < n:
            ch = text[k]
            if ch in '([':
                depth += 1
            elif ch in ')]':
                depth -= 1
            elif ch == ';' and depth <= 0:
                end = k + 1
                break
            elif ch == '{' and depth <= 0:
                end = match_close(text, k, '{', '}')
                break
            elif ch == '}' and depth <= 0:
                end = k  # attribute on last item of a block with nothing after; give up
                break
            k += 1
        item = text[j:end]
        mm = re.match(r'(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;', item)
        if mm:
            pm = re.search(r'path\s*=\s*"([^"]+)"', raw[a0:j])
            test_mods.append((mm.group(1), pm.group(1) if pm else None))
        removed.append((a0, end))
        for q in range(a0, end):
            if out[q] != '\n':
                out[q] = ' '
        pos = end
    new = ''.join(out)
    # lines fully inside removed ranges
    removed_lines = 0
    for a, b in removed:
        # An item spanning lines 15-23 has 8 newlines inside it and 9 lines. Count the 9th too,
        # unless the item ends exactly at a line break.
        removed_lines += text.count('\n', a, b) + (0 if b > a and text[b - 1] == '\n' else 1)
    return new, removed_lines, test_mods


def parse_tree(text, i):
    """Parse a path tree starting at i (just past a `::`). Returns list of segment lists."""
    n = len(text)
    while i < n and text[i].isspace():
        i += 1
    if i >= n:
        return [[]], i
    if text[i] == '{':
        end = match_close(text, i, '{', '}')
        res = []
        k = i + 1
        while k < end - 1:
            while k < end - 1 and (text[k].isspace() or text[k] == ','):
                k += 1
            if k >= end - 1:
                break
            sub, k2 = parse_item(text, k, end - 1)
            res.extend(sub)
            if k2 <= k:
                k += 1
            else:
                k = k2
        return res or [[]], end
    if text[i] == '*':
        return [['*']], i + 1
    return parse_item(text, i, n)


def parse_item(text, i, limit):
    m = IDENT.match(text, i)
    if not m or m.start() != i:
        return [[]], i
    name = m.group(0)
    k = m.end()
    j = k
    while j < limit and text[j].isspace():
        j += 1
    if text.startswith('::', j):
        sub, e = parse_tree(text, j + 2)
        if name == 'self':
            return sub, e
        return [[name] + s for s in sub], e
    # optional `as alias`
    am = re.compile(r'\s+as\s+(?:r#)?[A-Za-z_][A-Za-z0-9_]*').match(text, k)
    if am:
        k = am.end()
    if name == 'self':
        return [[]], k
    return [[name]], k


ANCHOR = re.compile(r'(?<![A-Za-z0-9_:])\$?(crate|super)\s*::')


INLINE_MOD = re.compile(r'(?<![A-Za-z0-9_])mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{')


def inline_mods(text):
    """[(start, end, name)] for every inline `mod name { ... }` block."""
    res = []
    for m in INLINE_MOD.finditer(text):
        res.append((m.end() - 1, match_close(text, m.end() - 1, '{', '}'), m.group(1)))
    return res


def effective(modpath, inl, off):
    return list(modpath) + [nm for a, b, nm in inl if a <= off < b]


def refs_in(text, file_modpath):
    """Yield (offset, [segments]) of crate-rooted paths referenced in text."""
    inl = inline_mods(text)
    for m in ANCHOR.finditer(text):
        kw = m.group(1)
        i = m.end()
        modpath = effective(file_modpath, inl, m.start())
        if kw == 'crate':
            base = []
        else:
            ups = 1
            while True:
                mm = re.compile(r'\s*super\s*::').match(text, i)
                if not mm:
                    break
                ups += 1
                i = mm.end()
            if ups > len(modpath):
                continue
            base = list(modpath[:len(modpath) - ups])
        paths, _ = parse_tree(text, i)
        for p in paths:
            yield m.start(), base + p


def ext_refs_in(text, ident):
    pat = re.compile(r'(?<![A-Za-z0-9_])' + re.escape(ident) + r'\s*::')
    for m in pat.finditer(text):
        paths, _ = parse_tree(text, m.end())
        for p in paths:
            yield m.start(), p


PUB_USE = re.compile(r'(?<![A-Za-z0-9_])pub(?:\s*\([^)]*\))?\s+use\s+')


def reexports(text, file_modpath, child_mods):
    """Names re-exported by this file, per module scope.

    Returns {modpath tuple: {name: ('ext', [segs]) | ('in', [segs])}}, {modpath tuple: [glob sources]}.
    """
    tables = collections.defaultdict(dict)
    globtab = collections.defaultdict(list)
    inl = inline_mods(text)
    for m in PUB_USE.finditer(text):
        modpath = effective(file_modpath, inl, m.start())
        names, globs = tables[tuple(modpath)], globtab[tuple(modpath)]
        i = m.end()
        end = text.find(';', i)
        if end < 0:
            continue
        stmt = text[i:end]
        lead = re.match(r'\s*(::)?\s*((?:r#)?[A-Za-z_][A-Za-z0-9_]*)', stmt)
        if not lead:
            continue
        first = lead.group(2)
        if first == 'crate':
            mm = re.match(r'\s*crate\s*::', stmt)
            paths, _ = parse_tree(stmt, mm.end())
            base = []
            kind = 'in'
        elif first == 'super':
            k = 0
            ups = 0
            while True:
                mm = re.compile(r'\s*super\s*::').match(stmt, k)
                if not mm:
                    break
                ups += 1
                k = mm.end()
            paths, _ = parse_tree(stmt, k)
            base = list(modpath[:max(0, len(modpath) - ups)])
            kind = 'in'
        elif first == 'self' or first in child_mods:
            continue  # re-export of own child: stays in this top module
        else:
            paths, _ = parse_item(stmt, lead.start(2), len(stmt))
            base = []
            kind = 'ext'
        # aliases
        alias = dict()
        for am in re.finditer(r'((?:r#)?[A-Za-z_][A-Za-z0-9_]*)\s+as\s+((?:r#)?[A-Za-z_][A-Za-z0-9_]*)', stmt):
            alias[am.group(1)] = am.group(2)
        for p in paths:
            full = base + p
            if not full:
                continue
            leaf = full[-1]
            if leaf == '*':
                globs.append((kind, full[:-1]))
                continue
            exported = alias.get(leaf, leaf)
            names[exported] = (kind, full)
    return tables, globtab


def is_test_file(rel):
    parts = rel.split(os.sep)
    base = parts[-1]
    if any(p in ('tests', 'test_support', 'testing') for p in parts[:-1]):
        return True
    return bool(re.match(r'^(tests?|test_support|[a-z0-9_]*_tests?|test_[a-z0-9_]*)\.rs$', base))


def modpath_of(rel):
    parts = rel[:-3].split(os.sep)
    if parts[-1] in ('mod', 'lib', 'main'):
        parts = parts[:-1]
    return parts


def tarjan(nodes, adj):
    idx, low, st, on, sccs, c = {}, {}, [], set(), [], [0]
    sys.setrecursionlimit(100000)

    def sc(v):
        idx[v] = low[v] = c[0]; c[0] += 1; st.append(v); on.add(v)
        for w in adj.get(v, ()):
            if w not in idx:
                sc(w); low[v] = min(low[v], low[w])
            elif w in on:
                low[v] = min(low[v], idx[w])
        if low[v] == idx[v]:
            comp = []
            while True:
                w = st.pop(); on.discard(w); comp.append(w)
                if w == v:
                    break
            sccs.append(comp)

    for v in nodes:
        if v not in idx:
            sc(v)
    return sccs


def eades(nodes, W):
    """Greedy feedback-arc ordering. Returns order top (callers) -> bottom (callees)."""
    w = lambda a, b: W.get((a, b), 0)
    left, right = [], []
    rem = set(nodes)
    while rem:
        changed = True
        while changed:
            changed = False
            for v in sorted(rem):
                if not any(w(v, u) for u in rem if u != v):
                    right.insert(0, v); rem.discard(v); changed = True
                elif not any(w(u, v) for u in rem if u != v):
                    left.append(v); rem.discard(v); changed = True
        if rem:
            v = max(sorted(rem), key=lambda v: sum(w(v, u) for u in rem) - sum(w(u, v) for u in rem))
            left.append(v); rem.discard(v)
    return left + right


def main():
    args = sys.argv[1:]
    root = args[0]
    out_json = None
    depth2 = set()
    ext_dirs = []
    crate_ident = 'zeroclaw_runtime'
    i = 1
    while i < len(args):
        if args[i] == '--json':
            out_json = args[i + 1]; i += 2
        elif args[i] == '--depth2':
            depth2 = set(args[i + 1].split(',')); i += 2
        elif args[i] == '--ext':
            ext_dirs.append(args[i + 1]); i += 2
        elif args[i] == '--crate-ident':
            crate_ident = args[i + 1]; i += 2
        else:
            i += 1

    files = []
    for d, _, fs in os.walk(root):
        for f in fs:
            if f.endswith('.rs'):
                files.append(os.path.relpath(os.path.join(d, f), root))
    files.sort()

    top = set()
    for rel in files:
        mp = modpath_of(rel)
        if mp:
            top.add(mp[0])

    info = {}
    test_declared = set()  # module paths (tuples) declared #[cfg(test)] mod x;
    test_paths = set()     # files pulled in through #[cfg(test)] #[path = "..."] mod x;
    for rel in files:
        raw = open(os.path.join(root, rel), encoding='utf-8', errors='replace').read()
        b = blank(raw)
        prod, removed_lines, tmods = strip_tests(raw, b)
        mp = modpath_of(rel)
        # the directory a file's child modules live in
        parts = rel[:-3].split(os.sep)
        child_base = parts[:-1] if parts[-1] in ('mod', 'lib', 'main') else parts
        for t, pth in tmods:
            if pth:
                test_paths.add(os.path.normpath(os.path.join(os.path.dirname(rel), pth)))
            else:
                test_declared.add(tuple(child_base + [t]))
        child_mods = set(re.findall(r'(?<![A-Za-z0-9_])mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*[;{]', prod))
        info[rel] = dict(raw=raw, prod=prod, total=raw.count('\n'), removed=removed_lines, mp=mp, child_mods=child_mods)

    # files that a test file pulls in through #[path] are test files too (fixpoint)
    PATH_MOD = re.compile(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]\s*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+[A-Za-z_][A-Za-z0-9_]*\s*;')
    grew = True
    while grew:
        grew = False
        for rel in list(test_paths):
            if rel not in info:
                continue
            for pm in PATH_MOD.finditer(info[rel]['raw']):
                q = os.path.normpath(os.path.join(os.path.dirname(rel), pm.group(1)))
                if q not in test_paths:
                    test_paths.add(q); grew = True

    # Files no `mod` declaration reaches are not compiled; leave them out (they used to be counted).
    DECL = re.compile(r'(?:#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]\s*)?(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;')
    reachable, todo = set(), ['lib.rs'] if 'lib.rs' in info else []
    while todo:
        rel = todo.pop()
        if rel in reachable or rel not in info:
            continue
        reachable.add(rel)
        parts = rel[:-3].split(os.sep)
        base = os.sep.join(parts[:-1]) if parts[-1] in ('mod', 'lib', 'main') else os.sep.join(parts)
        raw_b = blank(info[rel]['raw'])
        # keep the string contents of #[path = "..."] by matching on raw text at the same offsets
        for dm in re.finditer(r'(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;', raw_b):
            name = dm.group(1)
            before = info[rel]['raw'][max(0, dm.start() - 200):dm.start()]
            pm = re.search(r'#\s*\[\s*path\s*=\s*"([^"]+)"\s*\]\s*(?:#\s*\[[^\]]*\]\s*)*$', before)
            # a declaration inside an inline `mod outer { mod name; }` lives under outer/
            nest = [nm for a_, b_, nm in inline_mods(raw_b) if a_ <= dm.start() < b_]
            nbase = os.path.join(base, *nest) if nest else base
            if pm:
                todo.append(os.path.normpath(os.path.join(os.path.dirname(rel), pm.group(1))))
                todo.append(os.path.normpath(os.path.join(nbase, pm.group(1))))
            else:
                todo.append(os.path.normpath(os.path.join(nbase, name + '.rs')))
                todo.append(os.path.normpath(os.path.join(nbase, name, 'mod.rs')))
    orphan_files = sorted(set(info) - reachable)
    for rel in orphan_files:
        del info[rel]

    def file_is_test(rel):
        if is_test_file(rel) or rel in test_paths:
            return True
        mp = tuple(modpath_of(rel))
        for k in range(1, len(mp) + 1):
            if mp[:k] in test_declared:
                return True
        return False

    # lib.rs re-exports
    lib = info.get('lib.rs')
    lib_names = {}
    if lib:
        nm = reexports(lib['prod'], [], lib['child_mods'])[0].get((), {})
        # in lib.rs `pub use foo::Bar` has first segment = child mod: handle here
        for m in PUB_USE.finditer(lib['prod']):
            end = lib['prod'].find(';', m.end())
            stmt = lib['prod'][m.end():end]
            paths, _ = parse_item(stmt, len(stmt) - len(stmt.lstrip()), len(stmt))
            for p in paths:
                if p and p[0] in top and p[-1] != '*':
                    lib_names[p[-1]] = p
        for k, (kind, full) in nm.items():
            if kind == 'in':
                lib_names[k] = full

    # per-module re-export tables
    rex = {}
    rex_globs = {}
    for rel, d in info.items():
        if file_is_test(rel):
            continue
        nm, gl = reexports(d['prod'], d['mp'], d['child_mods'])
        for k, v in nm.items():
            rex.setdefault(k, {}).update(v)
        for k, v in gl.items():
            rex_globs.setdefault(k, []).extend(v)

    ITEM = re.compile(r'(?<![A-Za-z0-9_])(?:fn|struct|enum|trait|type|const|static|mod|union)\s+([A-Za-z_][A-Za-z0-9_]*)')
    defined = collections.defaultdict(set)
    for rel, d in info.items():
        if file_is_test(rel):
            continue
        inl = inline_mods(d['prod'])
        for im in ITEM.finditer(d['prod']):
            defined[tuple(effective(d['mp'], inl, im.start()))].add(im.group(1))
        for scope, tbl in reexports(d['prod'], d['mp'], d['child_mods'])[0].items():
            defined[scope].update(tbl)

    def classify(path):
        """Follow re-exports. Returns ('in', [segs]) final in-crate path, or ('ext', crate)."""
        for _ in range(4):
            if not path:
                return ('in', path)
            if path[0] not in top:
                if path[0] in lib_names:
                    path = list(lib_names[path[0]]) + path[1:]
                    continue
                return ('unresolved', path)
            # walk for a re-export hop at any prefix
            hopped = False
            for k in range(len(path) - 1, 0, -1):
                tbl = rex.get(tuple(path[:k]))
                if tbl and path[k] in tbl:
                    kind, full = tbl[path[k]]
                    if kind == 'ext':
                        return ('ext', full[0])
                    path = list(full) + path[k + 1:]
                    hopped = True
                    break
            if not hopped:
                # `pub use other_crate::x::*;` in the module: a name the module does not define
                # itself comes through that glob, so the reference is to the other crate.
                for k in range(len(path) - 1, 0, -1):
                    scope = tuple(path[:k])
                    ext = [g for kind, g in rex_globs.get(scope, []) if kind == 'ext']
                    if ext and path[k] not in defined.get(scope, ()):
                        return ('ext', ext[0])
                return ('in', path)
        return ('in', path)

    loc_prod = collections.Counter()
    loc_test = collections.Counter()
    E = collections.defaultdict(collections.Counter)       # real edges
    P = collections.defaultdict(collections.Counter)       # passthrough edges (via external re-export)
    syms = collections.defaultdict(collections.Counter)    # (src,dst) -> symbol path counter
    psyms = collections.defaultdict(collections.Counter)   # same, passthrough refs
    sites = collections.defaultdict(list)
    unresolved = collections.Counter()
    ext_dep = collections.defaultdict(collections.Counter)  # module -> external crate ident counts

    def node_of(mp):
        if not mp:
            return 'lib'
        if mp[0] in depth2 and len(mp) > 1:
            return mp[0] + '::' + mp[1]
        return mp[0]

    ext_pat = re.compile(r'(?<![A-Za-z0-9_:])(zeroclaw_[a-z_]+|zerorelay|zerocode)\s*::')

    TE = collections.defaultdict(collections.Counter)      # test-only edges
    tsyms = collections.defaultdict(collections.Counter)
    feats = collections.defaultdict(collections.Counter)   # cfg(feature = "...") names per node
    vis = collections.Counter()                            # pub(crate)/pub(super)/pub(in ..) count per node
    FEAT = re.compile(r'feature\s*=\s*"([^"]+)"')
    for rel, d in info.items():
        mp = d['mp']
        src = node_of(mp)
        for fm in FEAT.finditer(d['raw']):
            feats[src][fm.group(1)] += 1
        vis[src] += len(re.findall(r'pub\s*\(\s*(?:crate|super|in\b)', d['prod'])) if not file_is_test(rel) else 0
        if rel != 'lib.rs':
            # test-only references = references in the test-inclusive text minus production ones
            full = blank(d['raw'])
            allc = collections.Counter()
            for off, path in refs_in(full, mp):
                if path:
                    kind, final = classify(path)
                    if kind == 'in' and node_of(final) != src:
                        allc['::'.join(final)] += 1
            prodc = collections.Counter()
            if not file_is_test(rel):
                for off, path in refs_in(d['prod'], mp):
                    if path:
                        kind, final = classify(path)
                        if kind == 'in' and node_of(final) != src:
                            prodc['::'.join(final)] += 1
            for sym, c in (allc - prodc).items():
                tgt = node_of(sym.split('::'))
                TE[src][tgt] += c
                tsyms[(src, tgt)][sym] += c
        if file_is_test(rel):
            loc_test[src] += d['total']
            continue
        loc_prod[src] += d['total'] - d['removed']
        loc_test[src] += d['removed']
        text = d['prod']
        for m in ext_pat.finditer(text):
            ext_dep[src][m.group(1)] += 1
        if rel == 'lib.rs':
            continue
        for off, path in refs_in(text, mp):
            if not path:
                continue
            kind, final = classify(path)
            line = text.count('\n', 0, off) + 1
            if kind == 'unresolved':
                unresolved['::'.join(path[:2])] += 1
                continue
            if kind == 'ext':
                tgt = node_of(path) if path[0] in top else None
                if tgt and tgt != src:
                    P[src][tgt] += 1
                    psyms[(src, tgt)]['::'.join(path)] += 1
                continue
            tgt = node_of(final)
            if tgt == src:
                continue
            E[src][tgt] += 1
            sym = '::'.join(final)
            syms[(src, tgt)][sym] += 1
            if len(sites[(src, tgt)]) < 4:
                sites[(src, tgt)].append('%s:%d' % (rel, line))

    nodes = sorted(set(loc_prod) | set(E) | {t for s in E for t in E[s]})
    nodes = [x for x in nodes if x != 'lib']
    adj = {a: [b for b in E[a] if b in nodes] for a in nodes}
    sccs = tarjan(nodes, adj)
    big = max(sccs, key=len)
    W = {(a, b): E[a][b] for a in E for b in E[a]}

    print('crate src:', root)
    if orphan_files:
        print('files no mod declaration reaches (not counted): %d, %d lines: %s' % (
            len(orphan_files), sum(open(os.path.join(root, f), encoding='utf-8', errors='replace').read().count('\n') for f in orphan_files),
            ', '.join(orphan_files[:12])))
    print('production lines: %d   test lines: %d' % (sum(loc_prod.values()), sum(loc_test.values())))
    print('nodes: %d   real edges: %d (%d refs)   passthrough-only refs: %d' % (
        len(nodes), sum(len(E[a]) for a in E), sum(sum(E[a].values()) for a in E), sum(sum(P[a].values()) for a in P)))
    multi = [s for s in sccs if len(s) > 1]
    print('\ncycle groups (strongly connected components with >1 node): %d' % len(multi))
    for s in sorted(multi, key=lambda s: -sum(loc_prod[x] for x in s)):
        print('  %d nodes, %d prod lines: %s' % (len(s), sum(loc_prod[x] for x in s),
              ', '.join('%s(%.1fK)' % (x, loc_prod[x] / 1000) for x in sorted(s, key=lambda x: -loc_prod[x]))))
    order = eades(big, {k: v for k, v in W.items() if k[0] in big and k[1] in big})
    pos = {v: i for i, v in enumerate(order)}
    back = [(a, b, E[a][b]) for a in big for b in E[a] if b in pos and pos[b] < pos[a]]
    print('\nlargest cycle, greedy layering top -> bottom:\n  ' + ' > '.join(order))
    print('\nback-edges under that layering (%d edges, %d refs):' % (len(back), sum(x[2] for x in back)))
    for a, b, k in sorted(back, key=lambda x: x[2]):
        top_syms = ', '.join('%s x%d' % (s.split('::', 1)[1] if '::' in s else s, c) for s, c in syms[(a, b)].most_common(6))
        print('  %-16s -> %-16s %4d  [%s]' % (a, b, k, top_syms))
        print('  %-36s e.g. %s' % ('', ', '.join(sites[(a, b)][:3])))

    print('\nall edges inside the largest cycle (row uses column; refs):')
    for a in order:
        row = ', '.join('%s:%d' % (b, E[a][b]) for b in sorted(E[a], key=lambda b: -E[a][b]) if b in pos)
        print('  %-16s -> %s' % (a, row))

    cyc = set(big)
    print('\noutside the largest cycle:')
    rows = []
    for m in nodes:
        if m in cyc:
            continue
        uses = sorted(t for t in E[m] if t in cyc)
        used_by = sorted(k for k in cyc if m in E[k])
        side = 'above' if uses and not used_by else 'below' if used_by and not uses else 'both' if uses and used_by else 'free'
        rows.append((loc_prod[m], m, side, sorted(E[m]), sorted(k for k in nodes if m in E[k])))
    for n_, m, side, uses, usedby in sorted(rows, reverse=True):
        print('  %-24s %6d  %-5s uses=[%s] used-by=[%s]' % (m, n_, side, ','.join(uses), ','.join(usedby)))

    if unresolved:
        print('\nunresolved crate-root names (macros / unknown), top 15:')
        for k, v in unresolved.most_common(15):
            print('  %-40s %d' % (k, v))

    # external users of this crate
    ext_use = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
    for ed in ext_dirs:
        label = ed.rstrip('/')
        for d, dirs, fs in os.walk(ed):
            dirs[:] = [x for x in dirs if x not in ('target', 'node_modules', '.git', 'vendor')]
            for f in fs:
                if not f.endswith('.rs'):
                    continue
                p = os.path.join(d, f)
                if os.path.abspath(p).startswith(os.path.abspath(root) + os.sep):
                    continue
                try:
                    raw = open(p, encoding='utf-8', errors='replace').read()
                except OSError:
                    continue
                if crate_ident not in raw:
                    continue
                b = blank(raw)
                rel = os.path.relpath(p, ed)
                istest = is_test_file(rel) or '/tests/' in ('/' + rel) or rel.startswith('tests' + os.sep)
                prod, _, _ = strip_tests(raw, b)
                for text, kind in ((prod, 'prod'),) if not istest else ((b, 'test'),):
                    for off, path in ext_refs_in(text, crate_ident):
                        if not path:
                            continue
                        k2, final = classify(path)
                        tgt = final[0] if k2 == 'in' and final else ('(ext-reexport)' if k2 == 'ext' else '(root:%s)' % path[0])
                        ext_use[label][tgt][kind] += 1
                if not istest:
                    for off, path in ext_refs_in(b, crate_ident):
                        pass
    if ext_use:
        print('\nexternal users of `%s::<module>` (prod refs / test refs):' % crate_ident)
        for label in sorted(ext_use):
            row = ext_use[label]
            print('  %s' % label)
            for tgt in sorted(row, key=lambda t: -(row[t]['prod'] + row[t]['test'])):
                print('      %-28s %5d / %d' % (tgt, row[tgt]['prod'], row[tgt]['test']))

    if out_json:
        json.dump(dict(
            root=root, loc_prod=loc_prod, loc_test=loc_test,
            edges={a: dict(E[a]) for a in E},
            passthrough={a: dict(P[a]) for a in P},
            symbols={'%s->%s' % k: dict(v) for k, v in syms.items()},
            test_edges={a: dict(TE[a]) for a in TE},
            test_symbols={'%s->%s' % k: dict(v) for k, v in tsyms.items()},
            features={a: dict(feats[a]) for a in feats},
            restricted_vis=dict(vis),
            passthrough_symbols={'%s->%s' % k: dict(v) for k, v in psyms.items()},
            test_files=sorted(r for r in info if file_is_test(r)),
            sites={'%s->%s' % k: v for k, v in sites.items()},
            order=order, cycle=sorted(big),
            ext_crates={a: dict(ext_dep[a]) for a in ext_dep},
            ext_use={l: {t: dict(c) for t, c in r.items()} for l, r in ext_use.items()},
        ), open(out_json, 'w'), indent=1, sort_keys=True)


if __name__ == '__main__':
    main()
