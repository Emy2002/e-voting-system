FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc postgresql-client && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p logs

ENV FLASK_APP=backend
ENV PYTHONPATH=/app

EXPOSE 5000

# Run Flask in HTTP mode; Nginx handles HTTPS externally
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]