FROM python:3.9-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Generate self-signed TLS certificate for internal HTTPS sync
RUN mkdir -p /app/ssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /app/ssl/server.key \
    -out /app/ssl/server.crt \
    -subj "/C=US/ST=State/L=City/O=CloudProject/CN=app_server"

# Run uvicorn with SSL for HTTPS inter-node sync
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--ssl-keyfile", "/app/ssl/server.key", "--ssl-certfile", "/app/ssl/server.crt"]
