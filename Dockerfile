# Official image pinned by digest (python:3.12-slim, built 2026-10-06). Update the digest deliberately for OS patches.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
WORKDIR /app
# The optional ML layer adds scikit-learn (about 100 MB). Build with --build-arg INSTALL_ML=true to include it.
ARG INSTALL_ML=false
# Hash-locked installs: a substituted or tampered package fails the build.
COPY requirements.lock requirements-ml.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock \
    && if [ "$INSTALL_ML" = "true" ]; then pip install --no-cache-dir --require-hashes -r requirements-ml.lock; fi \
    && useradd --uid 1000 --create-home aegis
COPY app.py .
COPY aegis ./aegis
COPY templates ./templates
COPY static ./static
COPY deploy ./deploy
RUN mkdir /app/data && chown aegis:aegis /app/data
USER aegis
ENV AEGIS_BIND=0.0.0.0 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["python", "app.py"]
