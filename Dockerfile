FROM python:3.12-slim-bookworm
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 VENGUARD_DATA=/data VENGUARD_PORT=8098
WORKDIR /app
RUN groupadd --gid 10001 venguard && useradd --uid 10001 --gid venguard --no-create-home venguard && mkdir /data && chown venguard:venguard /data
COPY --chown=venguard:venguard app/ /app/
USER 10001:10001
VOLUME ["/data"]
EXPOSE 8098
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8098/health',timeout=3)"]
CMD ["python3", "server.py"]
