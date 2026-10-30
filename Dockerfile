FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.11.28 /uv /bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PYTHONUNBUFFERED=1
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY pdp_guardian ./pdp_guardian
COPY demo/declaration.yaml ./demo/declaration.yaml
RUN uv sync --frozen --no-dev && useradd --system app
ENV PATH="/app/.venv/bin:$PATH"
USER app
ENTRYPOINT ["pdp-guardian"]
CMD ["web", "--host", "0.0.0.0"]
