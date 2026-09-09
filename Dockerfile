FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir . \
    && python -m playwright install --with-deps chromium \
    && useradd --create-home --uid 10001 wappalyzer \
    && chown -R wappalyzer:wappalyzer /app /ms-playwright

USER wappalyzer

ENTRYPOINT ["wappalyzer"]
