FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application package
COPY py_log_analyzer/ ./py_log_analyzer/
COPY setup.py .

# Install the package
RUN pip install .

# Entrypoint for the CLI utility
ENTRYPOINT ["py-log-analyzer"]
