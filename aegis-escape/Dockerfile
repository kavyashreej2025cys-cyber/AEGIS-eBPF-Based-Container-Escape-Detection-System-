FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/data && useradd --uid 10001 --create-home aegis && chown -R aegis:aegis /app
USER aegis
EXPOSE 8080
# The service intentionally listens on loopback. Container uses host networking on Linux.
CMD ["python", "-m", "aegis.server", "--mode", "demo"]
