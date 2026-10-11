FROM python:3.12-slim
WORKDIR /app
# The optional ML layer adds scikit-learn (about 100 MB). Build with --build-arg INSTALL_ML=true to include it.
ARG INSTALL_ML=false
COPY requirements.txt requirements-ml.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && if [ "$INSTALL_ML" = "true" ]; then pip install --no-cache-dir -r requirements-ml.txt; fi \
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
