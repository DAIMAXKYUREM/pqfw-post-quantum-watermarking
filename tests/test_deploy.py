"""The deployment artefacts, checked without a Docker daemon.

A broken COPY path costs a full remote build round-trip to discover, and on a free tier
that is several minutes each time. These tests catch the mistakes that are checkable
statically: every path the Dockerfile copies must exist relative to the build context
the blueprint declares, and the staging directory for a Space must mirror the same
layout so that one Dockerfile serves both.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / "deploy"
DOCKERFILE = DEPLOY / "Dockerfile"

yaml = pytest.importorskip("yaml")


def copy_sources() -> list[str]:
    """Local paths the Dockerfile copies in, ignoring --from=stage copies."""
    sources: list[str] = []
    for line in DOCKERFILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line.upper().startswith("COPY ") or "--from=" in line:
            continue
        parts = line.split()[1:]
        sources.extend(parts[:-1])  # everything but the destination
    return sources


def test_every_dockerfile_copy_exists_at_the_repo_root() -> None:
    """The bug this file exists for.

    The Dockerfile was written against a staging directory where requirements.txt sat
    at the top, but the Render blueprint builds from the repository root, where it
    lives at deploy/. The build fails on the COPY, minutes into a remote job.
    """
    missing = [src for src in copy_sources() if not (ROOT / src.rstrip("/")).exists()]
    assert not missing, f"Dockerfile copies paths that do not exist at the repo root: {missing}"


def test_the_blueprint_sits_where_render_looks_for_it() -> None:
    """Render defaults to render.yaml at the repository root. Anywhere else and the
    Blueprint page reports "not found" and the operator has to know to type a path."""
    assert (ROOT / "render.yaml").exists()
    assert not (DEPLOY / "render.yaml").exists(), "two blueprints will drift apart"


def test_the_render_blueprint_matches_the_dockerfile() -> None:
    blueprint = yaml.safe_load((ROOT / "render.yaml").read_text(encoding="utf-8"))
    service = blueprint["services"][0]

    assert service["runtime"] == "docker"
    assert service["plan"] == "free"

    context = (ROOT / service["dockerContext"]).resolve()
    assert context == ROOT, "the blueprint must build from the repo root"
    assert (ROOT / service["dockerfilePath"].lstrip("./")).resolve() == DOCKERFILE.resolve()


def test_the_health_check_path_is_a_real_route() -> None:
    """Render marks a service unhealthy and restarts it if this 404s."""
    blueprint = yaml.safe_load((ROOT / "render.yaml").read_text(encoding="utf-8"))
    path = blueprint["services"][0]["healthCheckPath"]
    app_source = (ROOT / "web" / "app.py").read_text(encoding="utf-8")
    assert f'@app.get("{path}")' in app_source


def test_the_container_binds_the_port_the_host_injects() -> None:
    """Render, Koyeb and Cloud Run all inject PORT. A hard-coded port means the health
    check never passes and the deploy silently loops."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    cmd = [ln for ln in text.splitlines() if ln.startswith("CMD ")]
    assert cmd, "no CMD in the Dockerfile"
    assert "${PORT" in cmd[-1], "CMD must honour ${PORT}"
    assert not cmd[-1].startswith("CMD ["), "exec form does not expand ${PORT}"


def test_the_image_pins_only_the_declared_pqc_mechanisms() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    minimal = re.search(r'OQS_MINIMAL_BUILD="([^"]+)"', text)
    assert minimal, "the image must restrict liboqs to the algorithms this project declares"
    assert set(minimal.group(1).split(";")) == {"KEM_ml_kem_768", "SIG_ml_dsa_65"}
    assert "-DOQS_DIST_BUILD=ON" in text, (
        "without OQS_DIST_BUILD liboqs bakes in the build machine's micro-architecture "
        "and dies on an illegal instruction when the runtime CPU differs"
    )
    assert "ML-KEM-768' in kems" in text and "ML-DSA-65' in sigs" in text, (
        "the image must assert both mechanisms at build time, not at first request"
    )


def test_the_image_does_not_depend_on_openssl_headers() -> None:
    """The first Render build failed on this.

    OQS_USE_OPENSSL defaults to ON and makes cmake scan for OpenSSL >= 1.1.1. A slim
    Python base image carries libssl at runtime but not the development headers, so
    configure dies with "Could NOT find OpenSSL" several minutes into a remote build.
    Turning it off costs nothing for ML-KEM and ML-DSA, which are Keccak-based.
    """
    text = DOCKERFILE.read_text(encoding="utf-8")
    installs_headers = "libssl-dev" in text
    disables_openssl = "-DOQS_USE_OPENSSL=OFF" in text
    assert disables_openssl or installs_headers, (
        "either disable OQS_USE_OPENSSL or install libssl-dev; the default needs headers "
        "the slim image does not have"
    )


def test_the_library_lands_where_the_runtime_stage_copies_from() -> None:
    """GNUInstallDirs can resolve to lib/x86_64-linux-gnu on Debian, which would leave
    the COPY finding an empty lib/ and the failure surfacing only at import."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "-DCMAKE_INSTALL_LIBDIR=lib" in text
    assert "test -f /opt/oqs/lib/liboqs.so" in text, (
        "the builder stage must fail if the shared library is not where it is expected"
    )


def test_runtime_requirements_exclude_development_dependencies() -> None:
    # Comments are stripped first: the file explains which dev dependencies are
    # deliberately absent, and naming them is not the same as depending on them.
    lines = [
        line.split("#", 1)[0].strip().lower()
        for line in (DEPLOY / "requirements.txt").read_text(encoding="utf-8").splitlines()
    ]
    pinned = [line for line in lines if line]

    for dev_only in ("pytest", "matplotlib", "pypdfium2"):
        assert not any(line.startswith(dev_only) for line in pinned), (
            f"{dev_only} is not needed to serve the demo"
        )
    for needed in ("liboqs-python", "fastapi", "uvicorn", "numpy", "cryptography"):
        assert any(line.startswith(needed) for line in pinned), f"{needed} is missing"


def test_the_space_staging_mirrors_the_repo_layout(tmp_path, monkeypatch) -> None:
    """One Dockerfile has to work from the repo root and from a Space staging dir."""
    sys.path.insert(0, str(DEPLOY))
    import build_space

    monkeypatch.setattr(build_space, "STAGE", tmp_path / "space")
    staged = build_space.build()
    stage = tmp_path / "space"

    for src in copy_sources():
        assert (stage / src.rstrip("/")).exists(), f"staging is missing {src}"
    assert (stage / "README.md").exists()
    assert any(p.name == "index.html" for p in staged)


def test_staging_refuses_to_publish_key_material(tmp_path, monkeypatch) -> None:
    sys.path.insert(0, str(DEPLOY))
    import build_space

    stage = tmp_path / "space"
    monkeypatch.setattr(build_space, "STAGE", stage)
    build_space.build()

    (stage / "seal.key").write_bytes(b"\x00" * 32)
    with pytest.raises(SystemExit, match="refusing to stage"):
        build_space._sanity_check(sorted(p for p in stage.rglob("*") if p.is_file()))
