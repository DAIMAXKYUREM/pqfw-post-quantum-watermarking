# Deploying PQFW

Two artefacts, because they have different hosting needs.

## 1. The static results page — live, free

A recorded end-to-end run, the evaluation figures and the measured attack table. Every
number is produced by executing the real library at build time; the page says so, and
carries the commit and timestamp it was built from.

```bash
python deploy/build_static_site.py
python - <<'PY'
from huggingface_hub import HfApi
HfApi().upload_folder(
    repo_id="evildeity/pqfw-post-quantum-watermarking",
    repo_type="space", folder_path="deploy/.static")
PY
```

Live: https://evildeity-pqfw-post-quantum-watermarking.static.hf.space/

## 2. The interactive demo — a container

Hugging Face keeps **static** Spaces free for everyone but now requires PRO for any
Space that runs a server. PQFW needs a server: the whole claim is that liboqs does the
work, and reimplementing ML-KEM and the Tardos scorer in JavaScript to fit a static
host would replace the thing being demonstrated with an untested copy of it. So the
interactive demo ships as a container.

```bash
python deploy/build_space.py               # stage src/ + web/ + Dockerfile
docker build -f deploy/Dockerfile -t pqfw .
docker run --rm -p 7860:7860 pqfw          # http://localhost:7860
```

The image builds liboqs itself, with `OQS_MINIMAL_BUILD` restricted to ML-KEM-768 and
ML-DSA-65 — so the container physically cannot fall back to another algorithm — and
`OQS_DIST_BUILD=ON` so run-time CPU feature detection is used rather than baking in the
build machine's micro-architecture. A build-time assertion fails the image if either
mechanism is missing, rather than failing the first request.

### Free hosts that will run it

| host | free tier | how |
|---|---|---|
| **Render** | yes, sleeps after 15 min idle | `deploy/render.yaml` is a blueprint: push this repo to GitHub, then Render → New → Blueprint |
| **Koyeb** | one service | point it at the repo, Dockerfile path `deploy/Dockerfile` |
| **HF Spaces** | needs PRO for Docker | `python deploy/build_space.py`, then upload `deploy/.space` with `sdk: docker` |

`${PORT}` is honoured, so Render, Koyeb and Cloud Run all work without changes.
