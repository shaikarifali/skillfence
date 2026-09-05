FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml ./
COPY skillfence ./skillfence
COPY examples ./examples

RUN pip install --no-cache-dir -e .

ENTRYPOINT ["skillfence"]
CMD ["--help"]
