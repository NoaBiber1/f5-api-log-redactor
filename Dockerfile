
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create an unprivileged user
RUN useradd --uid 10001 --create-home \
    --shell /usr/sbin/nologin appuser

# Copy only the application files
COPY --chown=10001:10001 redactor/ ./redactor/
COPY --chown=10001:10001 rules.yaml ./rules.yaml

USER 10001:10001

EXPOSE 8080

ENTRYPOINT ["python", "-m", "redactor.service"]
CMD ["--host", "0.0.0.0", "--port", "8080", "--rules", "/app/rules.yaml"]
