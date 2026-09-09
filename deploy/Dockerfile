# PQFW demo image, for Hugging Face Spaces (Docker SDK) or any container host.
#
# liboqs is built at *image* build time and installed to /usr/local, so
# ctypes.util.find_library("oqs") finds it at import. liboqs-python will otherwise
# clone and compile it on first import, which on a free tier means the first visitor
# after a cold start waits several minutes.
#
# OQS_MINIMAL_BUILD compiles only the two mechanisms this project declares. That cuts
# the build from minutes to seconds and the image by a few hundred megabytes -- and it
# means the container physically cannot fall back to some other algorithm.
#
# OQS_DIST_BUILD is not optional for a container. Without it liboqs is compiled for the
# micro-architecture of whatever machine built the image and dispatches to, say, AVX2
# routines unconditionally; a host with an older CPU then dies on an illegal
# instruction. With it, the dispatch happens at run time via CPU feature detection.
# Build and run machines are rarely the same box on a free tier.

FROM python:3.11-slim AS liboqs

ARG LIBOQS_VERSION=0.16.0
RUN apt-get update && apt-get install -y --no-install-recommends \
        git cmake ninja-build gcc libc6-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "$LIBOQS_VERSION" \
        https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/build -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
        -DOQS_DIST_BUILD=ON \
        -DCMAKE_INSTALL_PREFIX=/opt/oqs \
    && cmake --build /tmp/build --parallel 4 \
    && cmake --install /tmp/build \
    && rm -rf /tmp/liboqs /tmp/build


FROM python:3.11-slim

COPY --from=liboqs /opt/oqs/lib/ /usr/local/lib/
COPY --from=liboqs /opt/oqs/include/ /usr/local/include/
RUN ldconfig

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src \
    HOME=/tmp

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ /app/src/
COPY web/ /app/web/

# Fail the build, not the first request, if the PQC mechanisms are not really there.
RUN python -c "\
import oqs, sys; \
kems = oqs.get_enabled_kem_mechanisms(); sigs = oqs.get_enabled_sig_mechanisms(); \
assert 'ML-KEM-768' in kems, kems; \
assert 'ML-DSA-65' in sigs, sigs; \
print('liboqs', oqs.oqs_version(), 'ML-KEM-768 and ML-DSA-65 available')" \
 && python -c "from pqfw import pqc; print(pqc.alg_report())"

# HF Spaces runs as a non-root user and expects the app on 7860.
RUN useradd -m -u 1000 pqfw && chown -R pqfw /app
USER pqfw

ENV PORT=7860
EXPOSE 7860
HEALTHCHECK --interval=60s --timeout=5s --start-period=20s \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','7860')+'/api/health')"

# Shell form so ${PORT} expands: Render, Koyeb and Cloud Run all inject the port they
# expect the process to bind, and a hard-coded 7860 makes the health check fail on all
# three. HF Spaces sets no PORT, so the default stands.
CMD python -m uvicorn app:app --app-dir /app/web --host 0.0.0.0 --port ${PORT:-7860}
