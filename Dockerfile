From python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY logwatch ./logwatch
COPY samples ./samples
RUN pip install --no-cache-dir -e .
RUN useradd -m app && chown -R app /app
USER app
ENTRYPOINT ["python", "-m", "logwatch"]
CMD ["--demo"]