FROM python:3.12-slim

WORKDIR /app

# Create honeypot log directory
RUN mkdir -p /var/log/honeypot

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Initialize the database at build time
RUN python -c "from app import init_db; init_db()"

EXPOSE 5000

ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]
