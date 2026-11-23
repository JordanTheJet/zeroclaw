#!/usr/bin/env python3
"""simmove.py: measure, not estimate, how many open PRs a module move would break.

For each scenario it builds a synthetic commit on BASE (no worktree, no writes to the shared
object store) and three-way merges every open PR head that touches the affected paths, using
the same merge machinery GitHub uses (merge-ort via `git merge-tree`). A PR counts only if it
merges cleanly with BASE today and stops merging cleanly once the move is in.

Scenarios: "pure" = files renamed byte-for-byte plus the one-line lib.rs re-export;
"rewritten" = the same rename plus the usual in-file path edits (`crate::M::x` -> `crate::x`),
which is what a hand-built extraction does.
"""
import collections, json, os, re, subprocess, sys, tempfile
repo = os.path.expanduser('~/git/zeroclaw-worktrees/runtime-detangle-probe')
BASE = 'e02b7fb6f6'
def run(args, env=None, inp=None, ok=(0,)):
    r = subprocess.run(args, cwd=repo, env=env, input=inp, capture_output=True, text=True)
    if r.returncode not in ok:
        raise RuntimeError('%s -> %d %s' % (' '.join(args[:4]), r.returncode, r.stderr[:300]))
    return r
common = run(['git', 'rev-parse', '--git-common-dir']).stdout.strip()
common = common if os.path.isabs(common) else os.path.join(repo, common)
tmp = '/tmp/rdp-objs'; os.makedirs(tmp, exist_ok=True)
ENV = dict(os.environ, GIT_OBJECT_DIRECTORY=tmp, GIT_ALTERNATE_OBJECT_DIRECTORIES=os.path.join(common, 'objects'),
           GIT_AUTHOR_NAME='sim', GIT_AUTHOR_EMAIL='sim@localhost', GIT_COMMITTER_NAME='sim', GIT_COMMITTER_EMAIL='sim@localhost')
entries = []
for l in run(['git', 'ls-tree', '-r', BASE]).stdout.splitlines():
    meta, path = l.split('\t', 1); mode, typ, sha = meta.split()
    entries.append((mode, sha, path))
blob = lambda sha: run(['git', 'cat-file', 'blob', sha], env=ENV).stdout
def hash_obj(text):
    return run(['git', 'hash-object', '-w', '--stdin'], env=ENV, inp=text).stdout.strip()
def commit(mapfn, edit=None):
    idx = tempfile.mktemp(prefix='rdp-idx-')
    env = dict(ENV, GIT_INDEX_FILE=idx)
    lines = []
    for mode, sha, path in entries:
        np = mapfn(path)
        if edit:
            new = edit(path, sha)
            if new is not None: sha = hash_obj(new)
        lines.append('%s %s\t%s' % (mode, sha, np))
    run(['git', 'update-index', '--index-info'], env=env, inp='\n'.join(lines) + '\n')
    tree = run(['git', 'write-tree'], env=env).stdout.strip()
    os.remove(idx)
    return run(['git', 'commit-tree', tree, '-p', BASE, '-m', 'sim'], env=ENV).stdout.strip()
RT = 'crates/zeroclaw-runtime/'
SRC = RT + 'src/'
LIB = SRC + 'lib.rs'
def mod_prefixes(m):
    return [SRC + m + '/', SRC + m + '.rs']
def move_mod(mods, crate, rewrite=False):
    def mapfn(p):
        for m in mods:
            if p.startswith(SRC + m + '/') or p == SRC + m + '.rs':
                return 'crates/%s/src/%s' % (crate, p[len(SRC):])
        return p
    def edit(p, sha):
        if p == LIB:
            t = blob(sha)
            for m in mods:
                t = re.sub(r'(?m)^pub mod %s;' % m, 'pub use %s::%s;' % (crate.replace('-', '_'), m), t)
            return t
        if rewrite and p.endswith('.rs'):
            for m in mods:
                if p.startswith(SRC + m + '/') or p == SRC + m + '.rs':
                    t = blob(sha)
                    t2 = re.sub(r'\bcrate::%s::' % m, 'crate::', t)
                    t2 = re.sub(r'\bcrate::(agent|tools|security|sop|cron|skills|observability|i18n|rpc|daemon|composition|hooks|approval|platform|health|util|live_config_authority)::', r'zeroclaw_runtime::\1::', t2)
                    return t2 if t2 != t else None
        return None
    return commit(mapfn, edit)
prs = json.load(open('/tmp/rdp-tools/open-prs.json'))
def touching(prefixes, extra=()):
    out = []
    for p in prs:
        fs = [f[0] for f in p['flist']]
        if any(f.startswith(x) if x.endswith('/') else f == x for f in fs for x in list(prefixes) + list(extra)):
            out.append(p)
    return out
_base = {}
def mt(a, n):
    r = run(['git', 'merge-tree', '--write-tree', '--name-only', a, 'refs/rdp/pr/%d' % n], env=ENV, ok=(0, 1, 128, 129))
    if r.returncode == 0: return None
    if r.returncode != 1: return {'error': r.stderr[:120]}
    kinds = collections.Counter(re.findall(r'^CONFLICT \(([^)]+)\)', r.stdout, re.M))
    return dict(kinds)
def base_clean(n):
    if n not in _base: _base[n] = mt(BASE, n) is None
    return _base[n]
scen = []
for m, crate in [('observability', 'zeroclaw-observability'), ('hooks', 'zeroclaw-hooks'), ('cron', 'zeroclaw-cron'), ('sop', 'zeroclaw-sop'),
                 ('security', 'zeroclaw-security'), ('skills', 'zeroclaw-skills'), ('daemon', 'zeroclaw-daemon'), ('doctor', 'zeroclaw-doctor'),
                 ('quickstart', 'zeroclaw-quickstart'), ('control_plane', 'zeroclaw-control-plane'), ('rpc', 'zeroclaw-rpc-server'),
                 ('tools', 'zeroclaw-agent-tools'), ('agent', 'zeroclaw-agent')]:
    scen.append((m + ' pure', mod_prefixes(m), [LIB], lambda m=m, c=crate: move_mod([m], c)))
for m, crate in [('observability', 'zeroclaw-observability'), ('cron', 'zeroclaw-cron'), ('sop', 'zeroclaw-sop'), ('security', 'zeroclaw-security')]:
    scen.append((m + ' rewritten', mod_prefixes(m), [LIB], lambda m=m, c=crate: move_mod([m], c, rewrite=True)))
scen.append(('locales+i18n pure', [RT + 'locales/', SRC + 'i18n.rs', SRC + 'generated_locales.rs'], [LIB],
             lambda: commit(lambda p: p.replace(RT + 'locales/', 'crates/zeroclaw-i18n/locales/', 1) if p.startswith(RT + 'locales/') else
                            ('crates/zeroclaw-i18n/src/' + p[len(SRC):] if p in (SRC + 'i18n.rs', SRC + 'generated_locales.rs') else p))))
scen.append(('whole crate rename', [RT], [], lambda: commit(lambda p: 'crates/zeroclaw-kernel/' + p[len(RT):] if p.startswith(RT) else p)))
res = {}
for name, prefixes, extra, mk in scen:
    c = mk()
    cand = touching(prefixes, extra)
    direct = {p['number'] for p in touching(prefixes)}
    clean = [p for p in cand if base_clean(p['number'])]
    broken = {}
    for p in clean:
        k = mt(c, p['number'])
        if k is not None: broken[p['number']] = k
    kinds = collections.Counter()
    for k in broken.values(): kinds.update(k.keys())
    ready_broken = sum(1 for p in clean if p['number'] in broken and not p['isDraft'])
    res[name] = dict(touching=len(direct), candidates=len(cand), clean_today=len(clean), newly_conflicting=len(broken),
                     newly_conflicting_ready=ready_broken, newly_conflicting_direct=len([n for n in broken if n in direct]), kinds=dict(kinds), prs=sorted(broken))
    print('%-22s touch=%3d merge-clean-today=%3d  newly-conflicting=%3d (ready %d; of which touch the module %d)  kinds=%s' % (
        name, len(direct), len(clean), len(broken), ready_broken, res[name]['newly_conflicting_direct'], dict(kinds)), flush=True)
json.dump(res, open('/tmp/rdp-simmove.json', 'w'), indent=1)
print('DONE')
