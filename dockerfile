FROM python:3.13.2-slim

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN mkdir -p /app/logs

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080
ENV PYTHONUNBUFFERED=1
CMD ["streamlit", "run", "dashboard.py", "--server.address=0.0.0.0"]