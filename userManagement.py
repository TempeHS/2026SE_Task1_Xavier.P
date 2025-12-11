import sqlite3 as sql
import bcrypt


### example
def getUsers(email):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT password FROM users WHERE email = ?", (email,))
    data = cur.fetchone()
    if data is None:
        con.close()
        return None
    data = data[0]
    con.close()
    return data


def insertContact(email, password):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    try:
        cur.execute(
            "INSERT INTO users (email, password) VALUES (?, ?)", (email, password)
        )
        con.commit()
        con.close()
        return True
    except sql.IntegrityError:
        con.close()
        return False
