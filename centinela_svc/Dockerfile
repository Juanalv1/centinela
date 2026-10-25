FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8000

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --create-home centinela
COPY domain ./domain
COPY application ./application
COPY adapters ./adapters
COPY web ./web
USER centinela

CMD ["sh", "-c", "exec python -m uvicorn web.app:app --host 0.0.0.0 --port ${PORT:-8000} --no-access-log"]
