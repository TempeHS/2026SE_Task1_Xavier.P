import sqlite3 as sql
import bcrypt


### example
def getUsers():
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM id7-tusers")
    con.close()
    return cur


def insertContact(email, password):
    con = sql.connect("database/data_source.db")
    cur = con.cursor()
    cur.execute("INSERT INTO emails (email) VALUES (?)", (email))
    cur.execute("INSERT INTO passwords (password) VALUES (?)", (password))
    con.commit()
    con.close()
