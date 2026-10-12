FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Headless Chromium for web screenshots (utils/screenshots.py)
RUN python -m playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN chmod +x /app/utils/installation/install.sh /app/utils/installation/entrypoint.sh

EXPOSE 10001

CMD ["/app/utils/installation/entrypoint.sh"]