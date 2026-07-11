from flask import Flask, render_template, request
from netshield_ml import run_netshield
import os

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    file = request.files["file"]
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    df, anomalies = run_netshield(filepath)

    return render_template(
        "result.html",
        total=len(df),
        anomaly_count=len(anomalies)
    )

app.run(debug=True)
