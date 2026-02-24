from flask import Flask, render_template, request
import requests
import re
from urllib.parse import urlparse
import cv2
import numpy as np
from PIL import Image

app = Flask(__name__)

# ------------------ Risk Function ------------------
def calculate_risk(url):
    risk_score = 0
    reasons = []

    parsed = urlparse(url)

    if parsed.scheme != "https":
        risk_score += 20
        reasons.append("No HTTPS (Not Secure)")

    if len(url) > 75:
        risk_score += 15
        reasons.append("URL is too long")

    if url.count('.') > 3:
        risk_score += 15
        reasons.append("Too many subdomains")

    suspicious_words = ["login", "verify", "update", "free", "bank", "secure", "account"]
    for word in suspicious_words:
        if word in url.lower():
            risk_score += 20
            reasons.append("Contains suspicious keyword")
            break

    ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
    if re.search(ip_pattern, parsed.netloc):
        risk_score += 30
        reasons.append("Uses IP address instead of domain")

    return risk_score, reasons


# ------------------ QR Reader (OpenCV) ------------------
def read_qr(file):
    image = Image.open(file)
    image_np = np.array(image)
    image_np = cv2.cvtColor(image_np, cv2.COLOR_RGB2BGR)

    detector = cv2.QRCodeDetector()
    data, bbox, _ = detector.detectAndDecode(image_np)

    if data:
        return data
    return None


# ------------------ Home Route ------------------
@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    risk_score = 0
    reasons = []
    extracted_url = None

    if request.method == "POST":

        file = request.files.get("qr_image")
        manual_url = request.form.get("url")

        if file and file.filename != "":
            extracted_url = read_qr(file)

        url = manual_url or extracted_url

        if url:
            if not url.startswith("http"):
                url = "http://" + url

            try:
                response = requests.get(url, timeout=5)
                risk_score, reasons = calculate_risk(url)

                if response.status_code != 200:
                    risk_score += 40
                    reasons.append("Website not responding properly")

            except:
                result = "Invalid or Unreachable URL 🔴"
                risk_score = 80
                reasons.append("Website unreachable")

            if result is None:
                if risk_score <= 30:
                    result = "Safe 🟢"
                elif risk_score <= 60:
                    result = "Medium Risk 🟡"
                else:
                    result = "High Risk 🔴"

    return render_template("index.html",
                           result=result,
                           risk_score=risk_score,
                           reasons=reasons,
                           extracted_url=extracted_url)


if __name__ == "__main__":
    app.run(debug=True)