from flask import Flask

app = Flask(__name__)
app.get("/health")(lambda: {"status": "ok"})
app.run(host="127.0.0.1", debug=True)
