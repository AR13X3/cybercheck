# CyberCheck sandboxed page fetcher. Built on the official Playwright Python image, which carries the
# matching Chromium build and all its OS dependencies. The playwright package and our app deps are
# installed on top (the image does not include the package). Pinned by tag AND digest below; the
# playwright==1.65.2 pin in requirements.txt must match the tag.
FROM mcr.microsoft.com/playwright/python:v1.65.2-noble@sha256:38dd67fc654b56b3cba611e4c8eb71cd33750e1cd29eea2a5dc00b484817a75f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1
# (noble's system Python is PEP 668 "externally managed"; this image is single-purpose, so installing
# into it directly is intended.)

WORKDIR /app
COPY requirements.txt .
# The base image already has the Chromium build under /ms-playwright, so no `playwright install` here.
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Runs as the image's unprivileged pwuser (set in compose.yaml). The API binds 0.0.0.0 INSIDE the
# gluetun VPN network namespace (an isolated netns, not the host): Docker publishes the port by DNAT to
# the namespace's bridge interface, so a loopback bind would be unreachable. compose publishes it to the
# host on 127.0.0.1 only, and the API itself is protected by the bearer FETCHER_TOKEN and an Origin check.
EXPOSE 8432
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8432", "--no-access-log", "--workers", "1"]
