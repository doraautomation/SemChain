# SemChain

SemChain is a decentralized, risk-adaptive middleware that adds behavioral validation to
distributed commit consensus. 

For every commit, SemChain

1. extracts the semantic change from the AST and classifies the commit as `LOW` or `HIGH` risk
   (Semantic Extraction),
2. checks the change with static rules and with the result of running the bug's tests, which are
   executed once by one validator and verified by all the others through a signed attestation
   (Commit Validity Check, Execute and Attest),
3. decides with a risk-adaptive protocol, where `LOW` blocks use a one-phase commit and `HIGH`
   blocks use a majority quorum (Risk-Adaptive Consensus).

The prototype is a single file, `semchain.py`. One MPI rank is one cluster, and the validators of a
cluster run as threads.

## Repository layout

```
semchain.py          the prototype (all modules)
requirements.txt     Python dependencies
scripts/setup.sh     one-time setup
BugsInPy/            created by setup (git clone of the benchmark)
repos/               project clones, created automatically on the first run
work/                test environments, created automatically
results/             outputs of each run
```

## Requirements

- Linux, macOS or WSL with `bash` and `git`
- Python 3.8 or newer
- An MPI implementation, for example `sudo apt install -y openmpi-bin libopenmpi-dev`
- Docker, only for the SWE-smith dataset (`sudo apt install -y docker.io`)

## Setup

```bash
bash scripts/setup.sh
```

This installs the Python packages, installs Python 3.8 with `uv` (used to build the BugsInPy test
environments) and clones BugsInPy. Project repositories and test environments are created on the
first run, so that run is slow.

## Running

Every MPI rank is one cluster of `--validators` validator threads.

```bash
# 4 clusters x 30 validators, all of BugsInPy
mpiexec -n 4 python semchain.py

# one project
mpiexec -n 4 python semchain.py --projects black

# exactly 192 commits (whole bugs, fix and reverse together)
mpiexec -n 4 python semchain.py --commits 192

# 4 clusters x 20 validators
mpiexec -n 4 python semchain.py --validators 20

A small run to check the installation:

```bash
mpiexec -n 2 python semchain.py --projects black --commits 20 --validators 5
```

### SWE-smith

SWE-smith uses one Docker image per project, and tests run in it without network access.

```bash
mpiexec -n 4 python semchain.py --dataset swesmith --swesmith-repo oauthlib
mpiexec -n 4 python semchain.py --dataset swesmith --swesmith-repo oauthlib --swesmith-methods pr_
```

`--swesmith-repo` is a substring of the repository name, and the matching rows are downloaded from
Hugging Face on the first run and cached in `work/swesmith/`.

## Labelled data

Every bug gives two commits.

| Commit id                 | Change         | Expected verdict                     |
|---------------------------|----------------|--------------------------------------|
| `<project>-<bug>-fix`       | buggy to fixed | accept (a correct change)            |
| `<project>-<bug>-introduce` | fixed to buggy | reject (re-introduces the bug)       |

## Outputs

Each run writes to `results/`.

| File              | Content                                                              |
|-------------------|----------------------------------------------------------------------|
| `commits.csv`     | one row per commit with tier, score, verdict, reason and fingerprint |
| `blocks.csv`      | one row per block with consensus path, votes, decision and expected outcome |
| `ledger.jsonl`    | the committed blocks                                                 |
| `timing.csv`      | time per component of the slowest cluster                            |
| `performance.csv` | one appended line per run, for the scalability experiments           |

Environment setup is measured separately and excluded from the total time and the throughput.

## Options

| Option                  | Default      | Meaning                                                        |
|-------------------------|--------------|----------------------------------------------------------------|
| `--dataset`             | `bugsinpy`   | `bugsinpy` or `swesmith`                                       |
| `--projects`            | all          | only these BugsInPy projects                                   |
| `--exclude`             | `keras-12,PySnooper-2` | bugs to skip, as `project-bug`                       |
| `--commits`             | `0` (all)    | use exactly this many commits, replayed if more are asked for than exist |
| `--repeat`              | `1`          | replay the labelled commits R times                            |
| `--validators`          | `30`         | validator threads per cluster                                  |
| `--block-size`          | `1`          | commits per block                                              |
| `--w`                   | `1.0`        | weight in the risk score                                       |
| `--theta`               | `2.0`        | risk threshold, a commit with score at least theta is `HIGH`   |
| `--critical-ops`        | `.*`         | regular expression of critical function names (Check 1)       |
| `--test-timeout`        | `300`        | seconds before a test run counts as a suspected infinite loop  |
| `--no-test-low`         | off          | `LOW` commits get static checks only, instead of also being tested |
| `--round-size`          | `8`          | validators that vote in each 2PQC round                        |
| `--exec-workers`        | `0`          | parallel test runs per cluster (0 = CPU cores divided by clusters) |
| `--faulty-validators`   | none         | validator ids whose repository serves tampered code            |
| `--lying-validators`    | none         | validator ids that sign false test results                     |
| `--pythons`             | auto         | for example `3.7=/path/python3.7,3.8=/path/python3.8`          |
| `--swesmith-repo`       | none         | SWE-smith project, part of the repository name                 |
| `--swesmith-methods`    | none         | bug-type prefixes, for example `pr_` or `func_pm_remove_cond`  |
| `--swesmith-file`       | none         | local JSONL copy of the dataset                                |
| `--seed`                | `0`          | seed for the commit order and the sampling                     |
| `--bugsinpy`, `--repos`, `--work`, `--out` | next to the script | directories     |

## How the prototype is organised

| Module in `semchain.py`  | Role                                                                 |
|--------------------------|----------------------------------------------------------------------|
| Local Repository         | file access through one `git cat-file --batch` process per project   |
| Diff-AST                 | statement-level structural difference between two versions of a file |
| Semantic Extraction      | fingerprint, risk score and tier of each commit and block            |
| Commit Validity Check    | five checks: guard removed, handler removed, lock count changed, failing execution, new version does not compile |
| Test Environments        | `uv` virtual environments for BugsInPy, Docker images for SWE-smith  |
| Execute and Attest       | executor selection, test run, Ed25519 attestation and its verification |
| Risk-Adaptive Consensus  | one-phase commit for `LOW` blocks, 2PQC for `HIGH` blocks            |

The executor of a commit is chosen among the validators of the cluster other than the proposer, from
the SHA-256 digest of the block seed and the commit identifier, so every validator can recompute the
choice.

## Notes

- The analysis covers Python code only. Projects with substantial C, C++ or Cython code are outside
  its reach.
- A commit that fails the static checks is not executed, since its verdict is already decided.
