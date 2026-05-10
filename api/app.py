from flask import Flask, request
import sqlite3
import subprocess
import bcrypt
import os

app = Flask(__name__)

# Secret key depuis variable d'environnement
SECRET_KEY = os.getenv("SECRET_KEY", "default-secret")


@app.route("/login", methods=["POST"])
def login():

    try:
        data = request.get_json()

        username = data.get("username")
        password = data.get("password")

        # Validation des entrées
        if not username or not password:
            return {
                "status": "error",
                "message": "Missing username or password"
            }, 400

        if len(username) > 50:
            return {
                "status": "error",
                "message": "Invalid username"
            }, 400

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        # Requête SQL paramétrée
        query = "SELECT * FROM users WHERE username=? AND password=?"

        cursor.execute(query, (username, password))

        result = cursor.fetchone()

        conn.close()

        if result:
            return {
                "status": "success",
                "user": username
            }

        return {
            "status": "error",
            "message": "Invalid credentials"
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }, 500


@app.route("/ping", methods=["POST"])
def ping():

    try:
        data = request.get_json()

        host = data.get("host", "")

        # Validation
        if not host:
            return {"error": "Host required"}, 400

        # Pas de shell=True
        output = subprocess.check_output(
            ["ping", "-c", "1", host],
            text=True
        )

        return {"output": output}

    except Exception as e:
        return {"error": str(e)}, 500


@app.route("/compute", methods=["POST"])
def compute():

    # eval supprimé pour sécurité
    return {
        "message": "Function disabled for security reasons"
    }


@app.route("/hash", methods=["POST"])
def hash_password():

    try:
        data = request.get_json()

        pwd = data.get("password", "")

        if not pwd:
            return {"error": "Password required"}, 400

        # bcrypt sécurisé
        hashed = bcrypt.hashpw(
            pwd.encode(),
            bcrypt.gensalt()
        )

        return {
            "bcrypt": hashed.decode()
        }

    except Exception as e:
        return {"error": str(e)}, 500


@app.route("/readfile", methods=["POST"])
def readfile():

    try:
        data = request.get_json()

        filename = data.get("filename", "test.txt")

        # Protection path traversal
        if ".." in filename or filename.startswith("/"):
            return {"error": "Invalid filename"}, 400

        with open(filename, "r") as f:
            content = f.read()

        return {"content": content}

    except Exception as e:
        return {"error": str(e)}, 500


@app.route("/debug", methods=["GET"])
def debug():

    # Informations sensibles supprimées
    return {
        "debug": False
    }


@app.route("/hello", methods=["GET"])
def hello():

    return {
        "message": "Welcome to the secure DevSecOps API"
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)