FROM python:3.11.9-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
COPY dashboard/requirements.txt /app/dashboard/requirements.txt

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt -r /app/dashboard/requirements.txt

RUN useradd -m -u 1000 dashboard

COPY ai_security_model.py /app/ai_security_model.py
COPY audit.py /app/audit.py
COPY realtime_threat_engine.py /app/realtime_threat_engine.py
COPY report_generator.py /app/report_generator.py
COPY config.yaml /app/config.yaml
COPY Dockerfile.vuln /app/Dockerfile.vuln
COPY Dockerfile.hardened /app/Dockerfile.hardened
COPY logger.py /app/logger.py
COPY db.py /app/db.py
COPY VERSION /app/VERSION
COPY app /app/app
COPY dashboard /app/dashboard

RUN mkdir -p /app/reports /app/runtime && \
    chown -R dashboard:dashboard /app

USER dashboard
WORKDIR /app/dashboard

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health').read()" || exit 1

CMD ["python", "app.py"]
