"""Add pull requests and issues to your GitHub activity overview.

Needs the GitHub CLI, logged in as the account that owns this repo:
    winget install GitHub.cli        (then reopen the terminal)
    gh auth login

Run from this repo folder:
    python graph_extras.py --prs 40 --issues 25

Notes
- PRs and issues can't be backdated: they all land on the day you run it.
  Run it a few times on different days so it spreads out.
- Each PR adds a small notes file on its own branch, is merged, and the branch is deleted.
- There is a pause between actions so GitHub doesn't rate-limit you.
"""
import argparse
import random
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

PR_TOPICS = ["Add notes", "Update docs", "Refactor notes", "Add examples", "Fix typos",
             "Improve readme", "Add checklist", "Update changelog", "Add todo list", "Tidy files"]
COAUTHOR = ""
ISSUE_TOPICS = ["Track progress", "Plan next steps", "Review notes", "Organise folders",
                "Add more examples", "Clean up old files", "Write summary", "Check links"]


def run(*cmd, capture=False):
    r = subprocess.run(cmd, text=True, capture_output=True)
    if r.returncode != 0:
        sys.exit(f"FAILED: {' '.join(cmd)}\n{r.stderr.strip()}")
    return r.stdout.strip() if capture else None


def make_pr(i: int) -> None:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    branch = f"notes/{stamp}-{i}"
    title = f"{random.choice(PR_TOPICS)} #{i}"
    run("git", "checkout", "-q", "-b", branch)
    note = Path("notes") / f"{stamp}-{i}.md"
    note.parent.mkdir(exist_ok=True)
    note.write_text(f"# {title}\n\nCreated {datetime.now():%Y-%m-%d %H:%M}\n", encoding="utf-8")
    run("git", "add", str(note))
    msg = title + (f"\n\nCo-authored-by: {COAUTHOR}" if COAUTHOR else "")
    run("git", "commit", "-q", "-m", msg)
    run("git", "push", "-q", "-u", "origin", branch)
    run("gh", "pr", "create", "--title", title, "--body", "Small update.", "--base", "main", "--head", branch)
    run("gh", "pr", "merge", branch, "--merge", "--delete-branch")
    run("git", "checkout", "-q", "main")
    run("git", "pull", "-q", "origin", "main")
    print(f"  PR {i}: merged '{title}'")


def make_issue(i: int) -> None:
    title = f"{random.choice(ISSUE_TOPICS)} #{i}"
    url = run("gh", "issue", "create", "--title", title, "--body", "To do.", capture=True)
    num = url.rstrip("/").split("/")[-1]
    # Heart On Your Sleeve: react with a heart
    run("gh", "api", "-X", "POST", f"repos/{{owner}}/{{repo}}/issues/{num}/reactions",
        "-f", "content=heart", "-H", "Accept: application/vnd.github+json")
    run("gh", "issue", "close", num, "--comment", "Done.")
    print(f"  Issue {i}: opened + closed '{title}'")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prs", type=int, default=20)
    ap.add_argument("--issues", type=int, default=15)
    ap.add_argument("--pause", type=float, default=4.0, help="seconds between actions")
    ap.add_argument("--coauthor", default="",
                    help='real GitHub user for Pair Extraordinaire, e.g. "Maryam <id+user@users.noreply.github.com>"')
    a = ap.parse_args()
    global COAUTHOR
    COAUTHOR = a.coauthor.strip()

    run("gh", "auth", "status")
    if run("git", "status", "--porcelain", "--untracked-files=no", capture=True):
        sys.exit("Commit or discard your changes first (git status is not clean).")
    run("git", "checkout", "-q", "main")
    run("git", "pull", "-q", "origin", "main")

    jobs = ["pr"] * a.prs + ["issue"] * a.issues
    random.shuffle(jobs)
    n_pr = n_is = 0
    for job in jobs:
        if job == "pr":
            n_pr += 1
            make_pr(n_pr)
        else:
            n_is += 1
            make_issue(n_is)
        time.sleep(a.pause + random.random() * 2)
    print(f"\nDone: {n_pr} PRs, {n_is} issues. The overview can take a few hours to update.")


if __name__ == "__main__":
    main()
