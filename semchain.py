import argparse
import ast
import csv
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import tempfile
import threading
import time
import warnings
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from mpi4py import MPI

comm = MPI.COMM_WORLD
rank = comm.Get_rank()
size = comm.Get_size()
HERE = os.path.dirname(os.path.abspath(__file__))
LOW, HIGH = "LOW", "HIGH"
PASS, FAIL = "PASS", "FAIL"


# Utilities
def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


def git(repo, *args):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    return r.returncode, r.stdout


def sh(cmd, cwd=None, env=None, timeout=None):
    try:
        r = subprocess.run(["bash", "-c", cmd], cwd=cwd, env=env, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return r.returncode, (r.stdout + r.stderr)[-3000:]
    except subprocess.TimeoutExpired:
        return "timeout", ""


def is_test_file(path):
    parts = path.lower().split("/")
    name = parts[-1]
    return (any(p in ("test", "tests", "testing") for p in parts[:-1])
            or name.startswith("test_") or name.endswith("_test.py")
            or name in ("conftest.py", "test.py"))


def read_lines(path):
    if not os.path.exists(path):
        return []
    raw = open(path, "rb").read()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")) or raw[1:2] == b"\x00":
        text = raw.decode("utf-16", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")
    text = text.replace("﻿", "").replace("\x00", "").replace("\r", "")
    return [line.strip() for line in text.split("\n") if line.strip()]


def read_info(path):
    info = {}
    for line in read_lines(path):
        m = re.match(r'\s*(\w+)\s*=\s*"?(.*?)"?\s*$', line)
        if m:
            info[m.group(1)] = m.group(2)
    return info


# Local Repository
class LocalRepo:
    def __init__(self, path):
        self.path, self.proc, self.lock = path, None, threading.Lock()

    def get_file(self, sha, path, is_new=False):
        with self.lock:
            if self.proc is None:
                self.proc = subprocess.Popen(["git", "-C", self.path, "cat-file", "--batch"],
                                             stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            self.proc.stdin.write(f"{sha}:{path}\n".encode())
            self.proc.stdin.flush()
            header = self.proc.stdout.readline().decode().split()
            if len(header) < 3 or header[1] != "blob":
                return None
            data = self.proc.stdout.read(int(header[2]))
            self.proc.stdout.read(1)
        return data.decode("utf-8", errors="replace")


class TamperedRepo:
    def __init__(self, inner):
        self.inner = inner

    def get_file(self, sha, path, is_new=False):
        src = self.inner.get_file(sha, path, is_new)
        return src + "\n_tampered_by_faulty_node = True\n" if src is not None and is_new else src


# Diff-AST
BODY_FIELDS = ("body", "orelse", "finalbody", "handlers", "cases")
TRY_NODES = ("Try", "TryStar", "ExceptHandler")
LOCK_WORDS = ("lock", "rlock", "semaphore", "condition", "mutex")


def shallow_signature(node):
    saved = {f: getattr(node, f) for f in BODY_FIELDS if hasattr(node, f)}
    for f in saved:
        setattr(node, f, [])
    text = ast.dump(node, annotate_fields=True, include_attributes=False)
    for f, v in saved.items():
        setattr(node, f, v)
    return hashlib.sha1(text.encode()).hexdigest()[:16]


def is_guard(node):
    if isinstance(node, ast.Assert):
        return True
    if isinstance(node, ast.If):
        if node.body and isinstance(node.body[0], (ast.Raise, ast.Return, ast.Continue, ast.Break)):
            return True
        for sub in ast.walk(node.test):
            if isinstance(sub, ast.Compare) and any(isinstance(o, (ast.Is, ast.IsNot)) for o in sub.ops):
                return True
            if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)
                    and sub.func.id in ("isinstance", "hasattr", "callable", "len")):
                return True
    return False


def lock_acquisitions(node):
    n = 0
    if isinstance(node, (ast.With, ast.AsyncWith)):
        n += sum(any(w in ast.dump(i.context_expr).lower() for w in LOCK_WORDS) for i in node.items)
    for field, value in ast.iter_fields(node):
        if field in BODY_FIELDS:
            continue
        for v in (value if isinstance(value, list) else [value]):
            if isinstance(v, ast.AST):
                n += sum(isinstance(s, ast.Call) and isinstance(s.func, ast.Attribute)
                         and s.func.attr == "acquire" for s in ast.walk(v))
    return n


def analyse_tree(tree, path):
    statements, guards, trys, locks, functions = [], Counter(), Counter(), Counter(), set()

    def visit(node, scope):
        if isinstance(node, (ast.stmt, ast.ExceptHandler)):
            statements.append((path, scope, type(node).__name__, shallow_signature(node)))
            key = f"{path}::{scope}"
            guards[key] += is_guard(node)
            trys[key] += type(node).__name__ in TRY_NODES
            if isinstance(node, ast.stmt):
                locks[key] += lock_acquisitions(node)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            scope = node.name if scope == "<module>" else f"{scope}.{node.name}"
            if not isinstance(node, ast.ClassDef):
                functions.add(f"{path}::{scope}")
        for f in BODY_FIELDS:
            for child in getattr(node, f, []) or []:
                visit(child, scope)

    for stmt in tree.body:
        visit(stmt, "<module>")
    return statements, guards, trys, locks, functions


def diff_ast(base_src, new_src, path):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return _diff_ast(base_src, new_src, path)


def _diff_ast(base_src, new_src, path):
    def parse(src):
        return ast.Module(body=[], type_ignores=[]) if src is None else ast.parse(src)
    try:
        base_tree = parse(base_src)
    except SyntaxError:
        return None, "base"
    try:
        new_tree = parse(new_src)
        if new_src is not None:
            compile(new_src, path, "exec")
    except SyntaxError as e:
        return None, f"{path}: new version does not compile (line {e.lineno}: {e.msg})"
    bs, bg, bt, bl, _ = analyse_tree(base_tree, path)
    ns, ng, nt, nl, nf = analyse_tree(new_tree, path)
    b, n = Counter(bs), Counter(ns)
    return {"added": sorted((n - b).elements()), "deleted": sorted((b - n).elements()),
            "deleted_guards": sorted(f for f in bg if ng[f] < bg[f]),
            "deleted_try": sorted(f for f in bt if nt[f] < bt[f]),
            "lock_base": {f: c for f, c in bl.items() if c},
            "lock_new": {f: c for f, c in nl.items() if c},
            "functions_new": sorted(nf)}, None


# Semantic Extraction
def extract_one(commit, L, w, theta):
    ast_diff = {"added": [], "deleted": [], "deleted_guards": [], "deleted_try": [],
                "lock_base": {}, "lock_new": {}, "functions_new": [], "errors": []}
    for path in commit["files"]:
        base = L.get_file(commit["base_sha"], path)
        new = L.get_file(commit["new_sha"], path, is_new=True)
        d, err = diff_ast(base, new, path)
        if err == "base":
            continue
        if err:
            ast_diff["errors"].append(err)
            continue
        for k in ("added", "deleted", "deleted_guards", "deleted_try", "functions_new"):
            ast_diff[k] += d[k]
        ast_diff["lock_base"].update(d["lock_base"])
        ast_diff["lock_new"].update(d["lock_new"])
    F = {"added": ast_diff["added"], "deleted": ast_diff["deleted"],
         "errors": ast_diff["errors"]}
    size_diff = len(ast_diff["added"]) + len(ast_diff["deleted"])
    score = w * size_diff
    return {"hash": sha256(json.dumps(F, sort_keys=True)),
            "ast_diff": ast_diff, "size": size_diff, "score": score,
            "tier": HIGH if score >= theta else LOW}


def semantic_extract_and_classify(commits, repos, w, theta):
    fps = [extract_one(c, repos[c["project"]], w, theta) for c in commits]
    tau_b = HIGH if any(f["tier"] == HIGH for f in fps) else LOW
    return fps, tau_b


# Commit Validity Check
def static_checks(fp, critical_ops):
    d = fp["ast_diff"]
    if d["errors"]:
        return FAIL, d["errors"][0]
    live = set(d["functions_new"])
    for fn in d["deleted_guards"]:
        if fn in live and critical_ops.search(fn.split("::")[-1].split(".")[-1]):
            return FAIL, f"guard removed in critical operation {fn}"
    for fn in d["deleted_try"]:
        return FAIL, f"exception handler removed in {fn}"
    for fn in set(d["lock_base"]) | set(d["lock_new"]):
        if d["lock_base"].get(fn, 0) != d["lock_new"].get(fn, 0):
            return FAIL, f"lock acquisitions changed in {fn}"
    return PASS, ""


def ast_validity_check(fp, commit, block, tau_b, critical_ops, exe):
    verdict, reason = static_checks(fp, critical_ops)
    if verdict == FAIL or (tau_b == LOW and not exe.get("test_low")):
        return verdict, reason
    return verify_execution(commit, fp["hash"], block, exe)


# Test Environments
def find_pythons(spec):
    found = dict(item.split("=", 1) for item in filter(None, spec.split(",")))
    for v in ("3.6", "3.7", "3.8"):
        if v in found:
            continue
        if shutil.which("uv"):
            r = subprocess.run(["uv", "python", "find", v], capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip():
                found[v] = r.stdout.strip()
                continue
        if shutil.which(f"python{v}"):
            found[v] = shutil.which(f"python{v}")
    return found


def env_spec(args, project, bug, pythons):
    d = os.path.join(args.bugsinpy, "projects", project, "bugs", bug)
    info = read_info(os.path.join(d, "bug.info"))
    wanted = ".".join(info.get("python_version", "3.8").split(".")[:2])
    pyver = wanted if wanted in pythons else min(pythons, key=lambda v: abs(float(v) - float(wanted)))
    reqs = [r for r in read_lines(os.path.join(d, "requirements.txt"))
            if not r.startswith(("#", "-e")) and "git+" not in r
            and not r.split("==")[0].strip().lower().replace("_", "-").startswith(project.lower())
            and not r.lower().startswith("pkg-resources")]
    setup = read_lines(os.path.join(d, "setup.sh"))
    local_install = re.compile(r"^(python3?\s+setup\.py\s+(install|develop)|pip3?\s+install\s+(-e\s+)?\.)")
    pip_setup = [l for l in setup if re.match(r"^pip3?\s+install\s", l) and not local_install.match(l)
                 and "-r requirements" not in l]
    run_setup = [l for l in setup if not re.match(r"^pip3?\s+install\s", l) and not local_install.match(l)]
    key = f"{project}-py{pyver}-{sha256(json.dumps([pyver, sorted(reqs), pip_setup]))[:12]}"
    return {"key": key, "project": project, "interp": pythons[pyver], "reqs": reqs,
            "pip_setup": pip_setup, "run_setup": run_setup,
            "tests": read_lines(os.path.join(d, "run_test.sh")),
            "test_files": [t for t in info.get("test_file", "").split(";") if t],
            "fixed": info.get("fixed_commit_id")}


def build_env(spec, envs_dir):
    if spec.get("docker"):
        return docker_pull(spec)
    path = os.path.join(envs_dir, spec["key"])
    if os.path.exists(os.path.join(path, ".ready")):
        return
    uv, py = shutil.which("uv"), os.path.join(path, "bin", "python")
    if uv:
        sh(f'"{uv}" venv -q --seed --python "{spec["interp"]}" "{path}"')
        install = f'"{uv}" pip install -q --python "{py}" '
    else:
        sh(f'"{spec["interp"]}" -m venv "{path}"')
        install = f'"{py}" -m pip install -q '
    sh(install + '"setuptools<58" "pip<24" wheel pytest', timeout=1200)
    req_file = os.path.join(path, "requirements.txt")
    with open(req_file, "w") as f:
        f.write("\n".join(spec["reqs"]) + "\n")
    if spec["reqs"] and sh(install + f'-r "{req_file}"', timeout=3600)[0] != 0:
        for r in spec["reqs"]:
            sh(install + f'"{r}"', timeout=1200)
    for line in spec["pip_setup"]:
        sh(install + re.sub(r"^pip3?\s+install\s+", "", line), timeout=1200)
    for pytest_version in ("pytest<7", "pytest<5"):
        if sh(f'"{py}" -c "import pytest"', timeout=120)[0] == 0:
            break
        sh(install + f'"{pytest_version}"', timeout=1200)
    open(os.path.join(path, ".ready"), "w").close()


PIP_NAMES = {"past": "future", "yaml": "PyYAML", "bs4": "beautifulsoup4", "dateutil": "python-dateutil",
             "PIL": "Pillow", "cv2": "opencv-python", "sklearn": "scikit-learn", "Crypto": "pycryptodome",
             "OpenSSL": "pyOpenSSL", "jwt": "PyJWT", "magic": "python-magic", "attr": "attrs"}
FIXTURE_PLUGINS = {"mocker": "pytest-mock<3.7", "requests_mock": "requests-mock",
                   "freezer": "pytest-freezegun", "httpbin": "pytest-httpbin"}


# Execute and Attest
def run_test(args, spec, envs_dir, sha):
    if spec.get("docker"):
        return run_docker_test(args, spec, sha)
    repo = os.path.join(args.repos, spec["project"])
    work = tempfile.mkdtemp(prefix="semchain_", dir=args.work)
    try:
        archive = subprocess.run(["git", "-C", repo, "archive", sha], capture_output=True)
        subprocess.run(["tar", "-x", "-C", work], input=archive.stdout, check=True)
        for t in spec["test_files"]:
            code, content = git(repo, "show", f"{spec['fixed']}:{t}")
            if code == 0:
                os.makedirs(os.path.dirname(os.path.join(work, t)) or work, exist_ok=True)
                with open(os.path.join(work, t), "w", encoding="utf-8") as f:
                    f.write(content)
        bindir = os.path.join(envs_dir, spec["key"], "bin")
        roots = [work] + [os.path.join(work, d) for d in ("lib", "src") if os.path.isdir(os.path.join(work, d))]
        env = dict(os.environ, PATH=bindir + os.pathsep + os.environ.get("PATH", ""),
                   VIRTUAL_ENV=os.path.dirname(bindir), PYTHONPATH=os.pathsep.join(roots),
                   PYTHONDONTWRITEBYTECODE="1")
        for line in spec["run_setup"]:
            sh(line, cwd=work, env=env, timeout=args.test_timeout * 4)
        status, output = "passed", ""
        for cmd in spec["tests"]:
            cmd = re.sub(r"^tox\s+", "pytest ", cmd)
            rc, output = sh(cmd, cwd=work, env=env, timeout=args.test_timeout)
            for _ in range(3):
                if rc in (0, "timeout"):
                    break
                missing = re.search(r"No module named '([A-Za-z0-9_]+)", output)
                if missing and missing.group(1).lower() != spec["project"].lower():
                    package = PIP_NAMES.get(missing.group(1), missing.group(1))
                elif "unrecognized arguments: --cov" in output:
                    package = "pytest-cov<3"
                elif re.search(r"fixture '(\w+)' not found", output) and \
                        re.search(r"fixture '(\w+)' not found", output).group(1) in FIXTURE_PLUGINS:
                    package = FIXTURE_PLUGINS[re.search(r"fixture '(\w+)' not found", output).group(1)]
                else:
                    break
                sh(f'"{os.path.join(bindir, "python")}" -m pip install -q "{package}"', timeout=600)
                rc, output = sh(cmd, cwd=work, env=env, timeout=args.test_timeout)
            if rc == "timeout":
                status = "timeout"
                break
            if rc != 0:
                status = "crashed" if rc < 0 or rc > 128 else "failed"
                break
        return status, sha256(output)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def canonical(att):
    return json.dumps({k: v for k, v in att.items() if k != "sig"}, sort_keys=True).encode()


def select_executor(block, commit_id, validators):
    candidates = [v for v in validators if v != block["proposer"]] or [block["proposer"]]
    return candidates[int(sha256(f"{block['seed']}|{commit_id}"), 16) % len(candidates)]


def execute_and_attest(args, commit, fp_hash, spec, envs_dir, key, executor, lying):
    status, out_hash = run_test(args, spec, envs_dir, commit["new_sha"])
    if lying:
        status = "failed" if status == "passed" else "passed"
    att = {"commit": commit["id"], "fp": fp_hash, "env": spec["key"],
           "tests": sha256("\n".join(spec["tests"])), "status": status,
           "output": out_hash, "executor": executor}
    att["sig"] = key.sign(canonical(att)).hex()
    return att


def verify_execution(commit, fp_hash, block, exe):
    att = exe["atts"].get(commit["id"])
    if att is None:
        return FAIL, "no execution result"
    e = att["executor"]
    if e != select_executor(block, commit["id"], exe["validators"]):
        return FAIL, f"result signed by validator {e}, which was not the selected executor"
    try:
        exe["pubkeys"][e].verify(bytes.fromhex(att["sig"]), canonical(att))
    except Exception:
        return FAIL, f"invalid signature on the result from validator {e}"
    if att["fp"] != fp_hash:
        return FAIL, "execution result is for different code (fingerprint mismatch)"
    if att["status"] == "passed":
        return PASS, ""
    return FAIL, {"timeout": "infinite loop suspected",
                  "crashed": "runtime crash detected"}.get(att["status"], "unhandled exception / failing test")


# Risk-Adaptive Consensus
def hash_integrity(block):
    for i, c in enumerate(block["commits"]):
        if sha256(c["content"]) != block["blh"][i]:
            return f"hash integrity violated for {c['id']}"
    return None


def node_validates(block, repos, args, critical_ops, exe):
    err = hash_integrity(block)
    if err:
        return False, err
    fps, _ = semantic_extract_and_classify(block["commits"], repos, args.w, args.theta)
    for c, f, expected in zip(block["commits"], fps, block["F"]):
        if f["hash"] != expected:
            return False, f"{c['id']}: fingerprint mismatch"
        verdict, reason = ast_validity_check(f, c, block, block["tier"], critical_ops, exe)
        if verdict != PASS:
            return False, f"{c['id']}: {reason}"
    return True, ""


# BugsInPy Dataset
def load_bug(args, project, bug):
    info = read_info(os.path.join(args.bugsinpy, "projects", project, "bugs", bug, "bug.info"))
    buggy, fixed = info.get("buggy_commit_id"), info.get("fixed_commit_id")
    if not buggy or not fixed:
        return []
    _, out = git(os.path.join(args.repos, project), "diff", "--name-only", buggy, fixed, "--", "*.py")
    files = [f for f in out.split() if not is_test_file(f)]
    if not files:
        return []
    commits = [{"id": f"{project}-{bug}-fix", "label": "ACCEPT", "base_sha": buggy, "new_sha": fixed},
               {"id": f"{project}-{bug}-introduce", "label": "REJECT", "base_sha": fixed, "new_sha": buggy}]
    for c in commits:
        c.update(project=project, bug=bug, files=files,
                 content=f"{c['base_sha']}\n{c['new_sha']}\n" + "\n".join(files))
    return commits


# SWE-smith Dataset
def swesmith_rows(args):
    if args.swesmith_file:
        with open(args.swesmith_file) as f:
            rows = [json.loads(line) for line in f if line.strip()]
    else:
        cache = os.path.join(args.work, "swesmith", f"{re.sub(r'[^A-Za-z0-9_.-]', '_', args.swesmith_repo)}.jsonl")
        if os.path.exists(cache):
            with open(cache) as f:
                rows = [json.loads(line) for line in f if line.strip()]
        else:
            from datasets import load_dataset
            print("downloading the SWE-smith dataset from Hugging Face (first run only) ...", flush=True)
            ds = load_dataset("SWE-bench/SWE-smith", split="train")
            want = args.swesmith_repo.lower()
            ds = ds.filter(lambda r: want in r["repo"].lower())
            rows = [dict(r) for r in ds]
            os.makedirs(os.path.dirname(cache), exist_ok=True)
            with open(cache, "w") as f:
                for r in rows:
                    f.write(json.dumps(r) + "\n")
    rows = [r for r in rows if args.swesmith_repo.lower() in r["repo"].lower()]
    if args.swesmith_methods:
        keep = tuple(m.strip() for m in args.swesmith_methods.split(","))
        rows = [r for r in rows if r["instance_id"].rsplit(".", 1)[-1].startswith(keep)]
    return rows


def swesmith_commits(args, rows):
    commits, skipped = [], 0
    by_repo = {}
    for r in rows:
        by_repo.setdefault(r["repo"], []).append(r)
    for repo, items in sorted(by_repo.items()):
        name = repo.split("/", 1)[1]
        path = os.path.join(args.repos, name)
        if not os.path.isdir(os.path.join(path, ".git")):
            print(f"cloning https://github.com/{repo}", flush=True)
            subprocess.run(["git", "clone", "-q", f"https://github.com/{repo}", path], check=True)
        _, out = git(path, "for-each-ref", "refs/remotes/origin", "--format=%(refname:short) %(objectname)")
        branches = dict(line.split() for line in out.splitlines() if " " in line)
        clean = git(path, "rev-parse", "HEAD")[1].strip()
        for r in items:
            iid = r["instance_id"]
            bug_sha = branches.get(f"origin/{iid}")
            files = [m.group(1) for m in re.finditer(r"^diff --git a/(\S+) b/", r["patch"], re.M)]
            files = [f for f in dict.fromkeys(files) if f.endswith(".py") and not is_test_file(f)]
            if not bug_sha or not files:
                skipped += 1
                continue
            f2p = r["FAIL_TO_PASS"]
            f2p = json.loads(f2p) if isinstance(f2p, str) else list(f2p)
            spec = {"docker": True, "key": r["image_name"], "image": r["image_name"], "project": name,
                    "tests": f2p, "patch": r["patch"], "bug_sha": bug_sha}
            for label, base, new, kind in (("ACCEPT", bug_sha, clean, "fix"), ("REJECT", clean, bug_sha, "introduce")):
                c = {"id": f"{iid}-{kind}", "label": label, "base_sha": base, "new_sha": new,
                     "project": name, "bug": iid, "files": files, "spec": spec}
                c["content"] = f"{base}\n{new}\n" + "\n".join(files)
                commits.append(c)
    return commits, skipped


def docker_pull(spec):
    if subprocess.run(["docker", "image", "inspect", spec["image"]], capture_output=True).returncode != 0:
        subprocess.run(["docker", "pull", "--platform", "linux/x86_64", spec["image"]],
                       capture_output=True, check=False)


def run_docker_test(args, spec, sha):
    work = tempfile.mkdtemp(prefix="semchain_docker_", dir=args.work)
    try:
        buggy = sha == spec["bug_sha"]
        with open(os.path.join(work, "bug.diff"), "w") as f:
            f.write(spec["patch"])
        tests = spec["tests"]
        if len(tests) > 500:
            tests = sorted({t.split("::")[0] for t in tests})
        import shlex
        script = ["cd /testbed", "git checkout -q -- . 2>/dev/null"]
        if buggy:
            script.append("git apply /work/bug.diff || patch --batch --fuzz=5 -p1 -i /work/bug.diff")
        script += ["source /opt/miniconda3/bin/activate", "conda activate testbed",
                   "pytest --disable-warnings --color=no --tb=no -q -p no:cacheprovider "
                   + " ".join(shlex.quote(t) for t in tests)]
        with open(os.path.join(work, "run.sh"), "w") as f:
            f.write("\n".join(script) + "\n")
        try:
            r = subprocess.run(["docker", "run", "--rm", "--platform", "linux/x86_64", "--network", "none",
                                "-v", f"{work}:/work:ro", spec["image"], "bash", "/work/run.sh"],
                               capture_output=True, text=True, errors="replace", timeout=args.test_timeout)
        except subprocess.TimeoutExpired:
            return "timeout", ""
        status = "passed" if r.returncode == 0 else ("crashed" if r.returncode > 128 else "failed")
        return status, sha256((r.stdout + r.stderr)[-3000:])
    finally:
        shutil.rmtree(work, ignore_errors=True)


# Main
class build_lock:
    def __init__(self, envs_dir, key):
        self.path = os.path.join(envs_dir, "." + re.sub(r"[^A-Za-z0-9_.-]", "_", key) + ".lock")

    def __enter__(self):
        while True:
            try:
                self.fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                return self
            except FileExistsError:
                time.sleep(1)

    def __exit__(self, *exc):
        os.close(self.fd)
        os.remove(self.path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bugsinpy", default=os.path.join(HERE, "BugsInPy"))
    ap.add_argument("--repos", default=os.path.join(HERE, "repos"))
    ap.add_argument("--work", default=os.path.join(HERE, "work"))
    ap.add_argument("--out", default=os.path.join(HERE, "results"))
    ap.add_argument("--projects", nargs="*", help="only these projects (default: all)")
    ap.add_argument("--exclude", default="keras-12,PySnooper-2")
    ap.add_argument("--w", type=float, default=1.0, help="weight w")
    ap.add_argument("--theta", type=float, default=2.0, help="risk threshold θ")
    ap.add_argument("--block-size", type=int, default=1, help="commits per block")
    ap.add_argument("--validators", type=int, default=30,
                    help="validator threads per cluster; every MPI rank is one cluster")
    ap.add_argument("--round-size", type=int, default=8,
                    help="validators that vote in each 2PQC round; voting stops as soon as the "
                         "outcome is decided (more than half agree, or a majority is impossible)")
    ap.add_argument("--exec-workers", type=int, default=0,
                    help="tests run in parallel per cluster (0 = CPU cores / clusters)")
    ap.add_argument("--critical-ops", default=".*", help="regex of critical function names (Check 1)")
    ap.add_argument("--test-timeout", type=int, default=300)
    ap.add_argument("--no-test-low", dest="test_low", action="store_false",
                    help="LOW risk commits get static checks only (default: every commit is also tested; "
                         "LOW blocks still go through the 1-phase commit)")
    ap.add_argument("--pythons", default="", help='e.g. "3.7=/path/python3.7,3.8=/path/python3.8"')
    ap.add_argument("--commits", type=int, default=0,
                    help="use exactly this many commits (whole bugs: fix + reverse pairs, "
                         "replayed if more are asked for than exist); 0 = all")
    ap.add_argument("--repeat", type=int, default=1,
                    help="replay the labelled commits R times as separate commits (scalability)")
    ap.add_argument("--faulty-validators", default="",
                    help="validator ids (0 .. n-1) whose repository serves tampered code")
    ap.add_argument("--lying-validators", default="",
                    help="validator ids (0 .. n-1) that sign false test results")
    ap.add_argument("--dataset", choices=["bugsinpy", "swesmith"], default="bugsinpy")
    ap.add_argument("--swesmith-repo", default="",
                    help="SWE-smith project to use, e.g. oauthlib, marshmallow, pandas (part of the repo name)")
    ap.add_argument("--swesmith-methods", default="",
                    help="only these bug types, comma-separated prefixes, e.g. pr_ or func_pm_remove_cond")
    ap.add_argument("--swesmith-file", default="", help="use a local JSONL copy of the dataset instead")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    critical_ops = re.compile(args.critical_ops)
    faulty = {int(x) for x in args.faulty_validators.split(",") if x.strip()}
    lying = {int(x) for x in args.lying_validators.split(",") if x.strip()}

    if args.dataset == "swesmith":
        pythons = {}
        problem = None if shutil.which("docker") else "SWE-smith needs Docker (sudo apt install -y docker.io)."
        if not args.swesmith_repo:
            problem = "choose a project with --swesmith-repo, e.g. --swesmith-repo oauthlib"
    else:
        pythons = find_pythons(args.pythons)
        problem = None if (os.name != "nt" and shutil.which("bash") and pythons) else (
            "needs Linux/macOS/WSL with bash, and Python 3.8 "
            "(pip install uv && uv python install 3.8, or --pythons).")
    if problem:
        if rank == 0:
            print("ERROR: " + problem)
        return

    V = args.validators
    my_validators = list(range(rank * V, rank * V + V))
    exec_workers = args.exec_workers or max(1, (os.cpu_count() or 2) // size)
    keys = {v: Ed25519PrivateKey.generate() for v in my_validators}
    pubkeys = {v: k_.public_key() for v, k_ in keys.items()}

    # Setup
    if args.dataset == "swesmith":
        loaded = None
        if rank == 0:
            rows = swesmith_rows(args)
            commits, skipped = swesmith_commits(args, rows)
            print(f"SWE-smith: {len(rows)} bugs of '{args.swesmith_repo}' "
                  f"({len(commits) // 2} usable, {skipped} skipped)", flush=True)
            loaded = commits
        commits = comm.bcast(loaded, root=0)
        bugs = []
    exclude = {x.strip() for x in args.exclude.split(",") if x.strip()}
    pdir = os.path.join(args.bugsinpy, "projects")
    if args.dataset == "bugsinpy":
        bugs = [(p, b) for p in sorted(os.listdir(pdir)) if not args.projects or p in args.projects
                for b in sorted((b for b in os.listdir(os.path.join(pdir, p, "bugs")) if b.isdigit()), key=int)
                if f"{p}-{b}" not in exclude]
    if rank == 0:
        for p in sorted({p for p, _ in bugs}):
            if not os.path.isdir(os.path.join(args.repos, p, ".git")):
                url = read_info(os.path.join(pdir, p, "project.info"))["github_url"]
                print(f"cloning {url}", flush=True)
                subprocess.run(["git", "clone", "-q", url, os.path.join(args.repos, p)], check=True)
    comm.Barrier()
    if args.dataset == "bugsinpy":
        mine = [(i, load_bug(args, p, b)) for i, (p, b) in enumerate(bugs) if i % size == rank]
        commits = [c for _, cs in sorted(x for part in comm.allgather(mine) for x in part) for c in cs]

    envs_dir = os.path.join(args.work, "envs")
    os.makedirs(envs_dir, exist_ok=True)
    if args.repeat > 1:
        commits = [dict(c, id=f"{c['id']}#{r}") for r in range(args.repeat) for c in commits]
    if args.commits > 0:
        pairs = {}
        for c in commits:
            pairs.setdefault(c["id"].rsplit("-", 1)[0], []).append(c)
        order = sorted(pairs)
        random.Random(args.seed).shuffle(order)
        chosen, r = [], 0
        while len(chosen) < args.commits:
            for bug in order:
                chosen += [dict(c, id=f"{c['id']}@{r}") if r else c for c in pairs[bug]]
                if len(chosen) >= args.commits:
                    break
            r += 1
        commits = chosen[:args.commits]
    random.Random(args.seed).shuffle(commits)
    shared = {p: LocalRepo(os.path.join(args.repos, p)) for p in {c["project"] for c in commits}}
    tampered = {p: TamperedRepo(r) for p, r in shared.items()}
    repos_of = lambda v: tampered if v in faulty else shared
    chunks = [commits[i:i + args.block_size] for i in range(0, len(commits), args.block_size)]
    proposer_of = lambda j: (j % size) * V + (j // size) % V
    my_blocks = [(j, cs) for j, cs in enumerate(chunks) if j % size == rank]
    if rank == 0:
        print(f"{len(commits)} commits -> {len(chunks)} blocks, {size} clusters x {V} validators, "
              f"each cluster works on its own blocks independently (θ={args.theta}, w={args.w})", flush=True)
    comm.Barrier()

    t_start = time.time()

    # Semantic Extraction
    t0 = time.time()
    blocks, fps_of, ast_times = [], {}, []
    for j, cs in my_blocks:
        v = proposer_of(j)
        ta = time.time()
        fps, tau_b = semantic_extract_and_classify(cs, repos_of(v), args.w, args.theta)
        ast_times += [(time.time() - ta) / len(cs)] * len(cs)
        blh = [sha256(c["content"]) for c in cs]
        fps_of[j] = fps
        blocks.append({"id": j, "proposer": v, "commits": cs, "tier": tau_b, "blh": blh,
                       "seed": sha256("|".join(blh)), "F": [f["hash"] for f in fps]})
    t_p1 = time.time() - t0

    # Execute and Attest
    t0 = time.time()
    todo = [(b, c, fh) for b in blocks if b["tier"] == HIGH or args.test_low
            for c, fh in zip(b["commits"], b["F"])]
    specs = {}
    for _, c, _ in todo:
        pb = (c["project"], c["bug"])
        if pb not in specs:
            specs[pb] = c["spec"] if "spec" in c else env_spec(args, pb[0], pb[1], pythons)
    for ek, spec in {s_["key"]: s_ for s_ in specs.values()}.items():
        with build_lock(envs_dir, ek):
            build_env(spec, envs_dir)
    t_env = time.time() - t0
    t0 = time.time()

    def execute(job):
        b, c, fh = job
        e = select_executor(b, c["id"], my_validators)
        if static_checks(extract_one(c, repos_of(e)[c["project"]], args.w, args.theta), critical_ops)[0] == FAIL:
            return None
        return execute_and_attest(args, c, fh, specs[(c["project"], c["bug"])], envs_dir,
                                  keys[e], e, e in lying)

    with ThreadPoolExecutor(max_workers=exec_workers) as pool:
        atts = {a["commit"]: a for a in pool.map(execute, todo) if a}
    exe = {"pubkeys": pubkeys, "atts": atts, "validators": my_validators, "test_low": args.test_low}
    t_exec = time.time() - t0

    # Risk-Adaptive Consensus
    t0 = time.time()
    decisions, lat_1pc, lat_2pqc, votes_used = {}, [], [], []
    for b in blocks:
        if b["tier"] == LOW:
            tb = time.time()
            ok, reason = node_validates(b, repos_of(b["proposer"]), args, critical_ops, exe)
            decisions[b["id"]] = {"path": "1PC", "agreed": int(ok), "votes": 1, "n": 1, "reason": reason,
                                  "decision": "Committed" if ok else "Rejected"}
            lat_1pc.append(time.time() - tb)
    t_1pc = time.time() - t0

    t0 = time.time()
    R = max(1, min(args.round_size, V))
    check_lock, check_cache = threading.Lock(), {}

    def vote(v, b):
        L = repos_of(v)
        key_ = (id(L), b["id"])
        with check_lock:
            if key_ not in check_cache:
                check_cache[key_] = node_validates(b, L, args, critical_ops, exe)
            return check_cache[key_]

    with ThreadPoolExecutor(max_workers=R) as pool:
        for b in blocks:
            if b["tier"] != HIGH:
                continue
            tb = time.time()
            agreed = rejected = 0
            reasons = Counter()
            for start in range(0, V, R):
                for ok, reason in pool.map(lambda v: vote(v, b), my_validators[start:start + R]):
                    agreed += ok
                    rejected += not ok
                    if not ok:
                        reasons[reason] += 1
                if agreed > V / 2 or rejected >= V / 2:
                    break
            committed = agreed > V / 2
            decisions[b["id"]] = {"path": "2PQC", "agreed": agreed, "votes": agreed + rejected, "n": V,
                                  "decision": "Committed" if committed else "Rejected",
                                  "reason": "; ".join(r for r, _ in reasons.most_common(2))}
            lat_2pqc.append(time.time() - tb)
            votes_used.append(agreed + rejected)
    t_2pqc = time.time() - t0
    t_cluster = time.time() - t_start

    my_rows = []
    for b in blocks:
        for c, f in zip(b["commits"], fps_of[b["id"]]):
            verdict, reason = ast_validity_check(f, c, b, b["tier"], critical_ops, exe)
            my_rows.append({"commit": c["id"], "project": c["project"], "label": c["label"],
                            "cluster": rank, "block": b["id"], "ast_diff": f["size"], "score": f["score"],
                            "tier": f["tier"], "block_tier": b["tier"], "executed": c["id"] in atts,
                            "verdict": verdict, "reason": reason, "fp_hash": f["hash"][:16]})

    # Results
    gathered = comm.gather({"rows": my_rows, "blocks": blocks, "decisions": decisions,
                            "t": (t_p1, t_env, t_exec, t_1pc, t_2pqc, t_cluster),
                            "ast": ast_times, "l1": lat_1pc, "l2": lat_2pqc, "votes": votes_used,
                            "executed": len(atts)}, root=0)
    if rank != 0:
        return
    rows = sorted((r for g_ in gathered for r in g_["rows"]), key=lambda r: r["block"])
    blocks = sorted((b for g_ in gathered for b in g_["blocks"]), key=lambda b: b["id"])
    decisions = {k_: v for g_ in gathered for k_, v in g_["decisions"].items()}
    os.makedirs(args.out, exist_ok=True)
    ledger, block_rows = [], []
    for b in blocks:
        d = decisions[b["id"]]
        if d["decision"] == "Committed":
            ledger.append({"block": b["id"], "tier": b["tier"],
                           "commits": [c["id"] for c in b["commits"]]})
        good = all(c["label"] == "ACCEPT" for c in b["commits"]) and b["proposer"] not in faulty
        block_rows.append({"block": b["id"], "cluster": b["proposer"] // V, "commits": len(b["commits"]),
                           "tier": b["tier"], "proposer": b["proposer"], "path": d["path"],
                           "agreed": d["agreed"], "votes": d["votes"], "n": d["n"], "decision": d["decision"],
                           "expected": "Committed" if good else "Rejected", "reason": d["reason"]})
    for name, data in (("commits.csv", rows), ("blocks.csv", block_rows)):
        with open(os.path.join(args.out, name), "w", newline="", encoding="utf-8") as f:
            wr = csv.DictWriter(f, fieldnames=list(data[0]))
            wr.writeheader()
            wr.writerows(data)
    with open(os.path.join(args.out, "ledger.jsonl"), "w") as f:
        f.writelines(json.dumps(x) + "\n" for x in ledger)

    slowest = lambda i: max(g_["t"][i] for g_ in gathered)
    t_p1, t_env, t_exec, t_1pc, t_2pqc, wall = (slowest(i) for i in range(6))
    busy = wall - t_env
    mean = lambda xs: sum(xs) / len(xs) if xs else 0.0
    ast_times = [x for g_ in gathered for x in g_["ast"]]
    l1 = [x for g_ in gathered for x in g_["l1"]]
    l2 = [x for g_ in gathered for x in g_["l2"]]
    votes_used = [x for g_ in gathered for x in g_["votes"]]
    tiers = Counter(r["tier"] for r in rows)
    paths = Counter(d["path"] for d in decisions.values())
    acc = lambda items, bad, rej: sum(rej(x) == bad(x) for x in items) / len(items)
    commit_acc = acc(rows, lambda r: r["label"] == "REJECT", lambda r: r["verdict"] == FAIL)
    block_acc = acc(block_rows, lambda b: b["expected"] == "Rejected", lambda b: b["decision"] == "Rejected")
    per_cluster = Counter(b["proposer"] // V for b in blocks)
    table = [
        ("Clusters x validator threads", f"{size} x {V}", "clusters work independently"),
        ("Blocks per cluster", " / ".join(str(per_cluster[i]) for i in range(size)), ""),
        ("Commits: LOW / HIGH", f"{tiers[LOW]} / {tiers[HIGH]}", ""),
        ("Blocks: 1PC (LOW) / 2PQC (HIGH)", f"{paths['1PC']} / {paths['2PQC']}", ""),
        ("AST analysis (Protocol 1)", f"{t_p1:.2f} s", f"{mean(ast_times) * 1000:.1f} ms per commit"),
        ("Test execution (LOW + HIGH, once)" if args.test_low else "Test execution (HIGH commits, once)",
         f"{t_exec:.2f} s",
         f"{sum(g_['executed'] for g_ in gathered)} commits executed"),
        ("1-phase commit (LOW blocks)", f"{t_1pc:.2f} s", f"{mean(l1) * 1000:.1f} ms per block"),
        ("2PQC (prepare + commit, early stop)", f"{t_2pqc:.2f} s",
         f"{mean(l2) * 1000:.0f} ms per block, {mean(votes_used):.1f} of {V} votes used"),
        ("Total (slowest cluster, excl. setup)", f"{busy:.2f} s", f"{len(rows) / busy:.2f} commits/s"),
        ("Environment setup (one-time)", f"{t_env:.1f} s", ""),
        ("Accuracy per commit / per block", f"{commit_acc:.1%} / {block_acc:.1%}", ""),
    ]
    print("\nTiming and results (each time = slowest cluster)")
    for name, value, extra in table:
        print(f"  {name:42}{value:>16}   {extra}")
    with open(os.path.join(args.out, "timing.csv"), "w", newline="") as f:
        wr = csv.writer(f)
        wr.writerow(["component", "value", "detail"])
        wr.writerows(table)
    perf = os.path.join(args.out, "performance.csv")
    new_file = not os.path.exists(perf)
    with open(perf, "a") as f:
        if new_file:
            f.write("clusters,validators_per_cluster,commits,low_commits,high_commits,blocks,ast_s,"
                    "execution_s,one_phase_s,twopqc_s,avg_votes_used,total_s,commits_per_s,accuracy\n")
        f.write(f"{size},{V},{len(rows)},{tiers[LOW]},{tiers[HIGH]},{len(blocks)},{t_p1:.2f},"
                f"{t_exec:.2f},{t_1pc:.2f},{t_2pqc:.2f},{mean(votes_used):.1f},{busy:.2f},"
                f"{len(rows) / busy:.3f},{commit_acc:.4f}\n")
    print(f"results in {args.out}")


if __name__ == "__main__":
    main()
