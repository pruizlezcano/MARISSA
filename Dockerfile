FROM python:3.11-slim

WORKDIR /marissa

RUN pip install poetry

RUN apt-get update && apt-get install -y \
    mafft \
    gcc \
    g++ \
    libfuzzy-dev \
    && rm -rf /var/lib/apt/lists/*

ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

COPY pyproject.toml poetry.lock ./
COPY marissa ./marissa
RUN touch README.md

RUN poetry install --without dev \
    && rm -rf $POETRY_CACHE_DIR

ENTRYPOINT ["poetry", "run", "marissa"]
