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


def insertContact(email, name, password):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    try:
        cur.execute(
            "INSERT INTO users (email, name,  password) VALUES (?, ?)",
            (email, name, password),
        )
        con.commit()
        con.close()
        return True
    except sql.IntegrityError:
        con.close()
        return False


def getLogs(email):
    con = sql.connect("/databasefiles/database.db")
    cur = con.cursor()
    cur.execute(
        "SELECT id, proj_name , entry_time, repo FROM devlogs WHERE email = ?", (email,)
    )
    data = cur.fetchall()
    con.close()
    return data


def addLogs(
    email, name, proj_name, start_time, end_time, entry_time, time_worked, repo, notes
):
    con = sql.connect("/databasefiles/database.db")
    cur = con.cursor()
    cur.execute(
        "INSERT INTO devlogs (email, name, proj_name, start_time, end_time, entry_time, time_worked, repo, notes) VALUES (?,?,?,?,?,?,?,?)",
        (
            email,
            name,
            proj_name,
            start_time,
            end_time,
            entry_time,
            time_worked,
            repo,
            notes,
        ),
    )
    con.commit()
    con.close()
    return True
