FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY remediator.py .

# Run as non-root user
RUN useradd -m -u 1000 remediator
USER remediator

CMD ["python", "-u", "remediator.py"]
