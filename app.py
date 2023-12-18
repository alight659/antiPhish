from flask import Flask, render_template, request
import phishcheck

app = Flask(__name__)

@app.route("/", methods=["GET","POST"])
def index():
    req = request.form.get("url")
    res = phishcheck.check_url(str(request.form.get("url")))
    if req:
        if res == False:
            return render_template("index.html", warning="SAFE", color="green", status=f"\"{req}\" is not a Phishing website")
        elif res == True:
            return render_template("index.html", warning="DANGER", color="red", status=f"\"{req}\" is potentially a Phishing Website.")
        return render_template("index.html")
    return render_template("index.html")

@app.route("/safety")
def safety():
    return render_template("safety.html")
