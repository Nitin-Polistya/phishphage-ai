FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
RUN useradd --create-home --uid 10001 appuser

COPY apps/api/requirements.txt /app/apps/api/requirements.txt
RUN pip install --no-cache-dir -r /app/apps/api/requirements.txt

COPY apps/api/app /app/apps/api/app
COPY apps/api/scripts /app/apps/api/scripts
COPY services/ml/models/registry.json /app/services/ml/models/registry.json

RUN mkdir -p /app/services/ml/artifacts /app/services/ml/models \
    && chown -R appuser:appuser /app
USER appuser

ENV PYTHONPATH=/app/apps/api \
    HOST=0.0.0.0 \
    PORT=8000 \
    ENVIRONMENT=production \
    ML_REQUIRED=true \
    ML_REGISTRY_PATH=/app/services/ml/models/registry.json \
    ML_ARTIFACT_PATH=/app/services/ml/artifacts/fitted_pipeline.joblib

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('PORT', '8000') + '/api/v1/health', timeout=4)"

CMD ["sh", "-c", "python /app/apps/api/scripts/provision_model_artifact.py && exec python -m uvicorn app.main:app --host ${HOST} --port ${PORT} --workers ${WEB_CONCURRENCY:-1}"]
