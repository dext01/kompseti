import os
from flask import Flask, jsonify
import psycopg2

app = Flask(__name__)

def get_db_connection():
    conn = psycopg2.connect(
        host=os.getenv('DB_HOST', 'postgres-db'),
        database=os.getenv('DB_NAME', 'myapp'),
        user=os.getenv('DB_USER', 'stepan'),
        password=os.getenv('DB_PASSWORD', 'secret123'),
        port=os.getenv('DB_PORT', '5432')
    )
    return conn

@app.route('/')
def hello():
    return jsonify({"message": "Hello from Flask app!"}), 200

@app.route('/health')
def health():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT 1')
        cur.close()
        conn.close()
        return jsonify({"status": "OK", "database": "connected"}), 200
    except Exception as e:
        return jsonify({"status": "ERROR", "database": "disconnected", "error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
