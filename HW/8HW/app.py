from flask import Flask
from flask.templating import render_template

app = Flask(__name__)

@app.route("/", methods=["GET"])
@app.route("/index.html", methods=['GET'])
def index():
    return render_template("index.html")

@app.route("/generic", methods=["GET"])
@app.route("/generic.html", methods=["GET"])
def generic():
    return render_template("generic.html")

@app.route("/elements", methods=["GET"])
@app.route("/elements.html", methods=["GET"])
def elements():
    return render_template("elements.html")

app.run("127.0.0.1", port=14741, debug=True)