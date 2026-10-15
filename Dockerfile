FROM python:3.10-slim
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN pip install --upgrade pip setuptools wheel jaraco.context msgpack
COPY FORENSIC/requirements_minimal.txt .
RUN pip install --no-cache-dir -r requirements_minimal.txt
COPY Authentication/ ./Authentication/
COPY database/ ./database/
COPY FORENSIC/ ./FORENSIC/

EXPOSE 5000

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
