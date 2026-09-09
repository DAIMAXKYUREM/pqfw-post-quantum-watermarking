"""Assemble the Hugging Face Space payload into a staging directory.

The Space repo is not the project repo. It carries only what the demo needs to run --
the library, the web app, a Dockerfile and a README with the Space frontmatter -- and
none of the tests, evaluation harness, figures or development dependencies. Keeping the
two separate is also why the project README can stay a project README instead of
acquiring a YAML header for a hosting provider.

    python deploy/build_space.py            # stage into deploy/.space
    python deploy/build_space.py --check    # list what would be staged
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
STAGE = DEPLOY / ".space"

# Nothing here is secret, but being explicit beats a broad copy: a stray state/
# directory in a Space repo would publish sealed-store key material.
EXCLUDE = shutil.ignore_patterns(
    "__pycache__", "*.pyc", "*.pyo", ".pytest_cache", "state", "demo_state", "*.egg-info"
)


def build() -> list[Path]:
    if STAGE.exists():
        shutil.rmtree(STAGE)
    STAGE.mkdir(parents=True)

    shutil.copytree(ROOT / "src", STAGE / "src", ignore=EXCLUDE)
    shutil.copytree(ROOT / "web", STAGE / "web", ignore=EXCLUDE)
    shutil.copy2(DEPLOY / "Dockerfile", STAGE / "Dockerfile")
    # Mirrors the repo layout: the Dockerfile is written for a repo-root build
    # context, so requirements.txt has to sit at deploy/ here too.
    (STAGE / "deploy").mkdir(exist_ok=True)
    shutil.copy2(DEPLOY / "requirements.txt", STAGE / "deploy" / "requirements.txt")
    shutil.copy2(DEPLOY / "SPACE_README.md", STAGE / "README.md")
    (STAGE / ".gitattributes").write_text("* -text\n", encoding="utf-8")

    staged = sorted(p for p in STAGE.rglob("*") if p.is_file())
    _sanity_check(staged)
    return staged


def _sanity_check(staged: list[Path]) -> None:
    """Refuse to stage anything that would publish key material."""
    forbidden = ("seal.key", "distributor.sealed", "ledger.json")
    for path in staged:
        if path.name in forbidden or path.suffix in (".sealed", ".key"):
            raise SystemExit(f"refusing to stage {path.relative_to(STAGE)}")
    required = {"Dockerfile", "requirements.txt", "README.md"}
    present = {p.name for p in staged}
    missing = required - present
    if missing:
        raise SystemExit(f"staging is incomplete, missing {sorted(missing)}")
    if not (STAGE / "web" / "static" / "index.html").exists():
        raise SystemExit("staging is missing the front end")
    if not (STAGE / "src" / "pqfw" / "pqc.py").exists():
        raise SystemExit("staging is missing the library")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="list files and exit")
    args = parser.parse_args()

    staged = build()
    total = sum(p.stat().st_size for p in staged)
    for path in staged:
        print(f"  {path.relative_to(STAGE).as_posix():<44} {path.stat().st_size:>8,} B")
    print(f"\n{len(staged)} files, {total:,} bytes staged in {STAGE}")
    if not args.check:
        print("\nupload with:")
        print(f"  hf upload <user>/<space> {STAGE} . --repo-type=space")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
