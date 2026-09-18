"""Lab Ch.4 - Web app VULNERABLE (co chu y).
- Ket noi bang 'sa' (sysadmin) -> SQLi ke thua quyen sysadmin -> RCE.
- Dung pymssql de khoi can ODBC Driver 18. Tuong duong ban pyodbc trong PDF.
- Chay: python app.py  (nghe 0.0.0.0:5000)
"""
from flask import Flask, request, render_template
import pymssql

app = Flask(__name__)

DB_CONF = {"server": "localhost", "port": 1433, "user": "sa", "password": "Password1", "database": "shopdb"}


def get_conn():
    cn = pymssql.connect(**DB_CONF)
    cn.autocommit(True)  # nhu pyodbc autocommit=True trong PDF: stacked query co hieu luc ngay
    return cn


@app.route("/product")
def product():
    pid = request.args.get("id", "1")
    cn = get_conn()
    cur = cn.cursor()
    q = "SELECT id,name,price FROM products WHERE id = " + pid  # LOI SQLi: ghep chuoi
    try:
        cur.execute(q)
        rows = cur.fetchall()
        cn.close()
        return "<br>".join(str(tuple(r)) for r in rows) or "no rows"
    except Exception as e:
        try:
            cn.close()
        except Exception:
            pass
        return "SQL error: " + str(e)


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
