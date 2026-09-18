"""Lab Ch.4 - Ban VA (sau Phan 7 phong thu).
- Login quyen toi thieu shop_ro (db_datareader) + tham so hoa -> chan SQLi, chan RCE.
"""
from flask import Flask, request
import pymssql

app = Flask(__name__)

DB_CONF = {"server": "localhost", "port": 1433, "user": "shop_ro", "password": "ShopRo_Manh_NgauNhien_2026!", "database": "shopdb"}


@app.route("/product")
def product():
    pid = request.args.get("id", "1")
    cn = pymssql.connect(**DB_CONF)
    cur = cn.cursor()
    try:
        cur.execute("SELECT id,name,price FROM products WHERE id = %s", (pid,))  # tham so hoa
        rows = cur.fetchall()
        cn.close()
        return "<br>".join(str(tuple(r)) for r in rows) or "no rows"
    except Exception as e:
        try:
            cn.close()
        except Exception:
            pass
        return "SQL error: " + str(e)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
