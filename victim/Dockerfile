FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8000

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --no-create-home --shell /usr/sbin/nologin app \
    && cp /bin/sleep /usr/local/bin/db-sim \
    && command -v setpriv

COPY app.py pyme.py schema.sql roles.sql entrypoint.sh ./
COPY jobs/ ./jobs/
RUN sed -i 's/\r$//' entrypoint.sh && chmod 0755 entrypoint.sh && chmod -R a+rX /app

# Entrypoint starts as root only to launch the protected root process,
# then drops to the unprivileged `app` user for the API.
ENTRYPOINT ["/app/entrypoint.sh"]
