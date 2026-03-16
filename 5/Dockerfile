FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

ENV DB_HOST=postgres-db
ENV DB_NAME=myapp
ENV DB_USER=stepan
ENV DB_PASSWORD=secret123
ENV DB_PORT=5432

EXPOSE 5000

CMD ["python", "app.py"]
