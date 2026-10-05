FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --uid 1000 --create-home aegis
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
