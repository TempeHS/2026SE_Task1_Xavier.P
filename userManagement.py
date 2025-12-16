import sqlite3 as sql
import bcrypt
import datetime


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
            "INSERT INTO users (email, name,  password) VALUES (?, ?, ?)",
            (email, name, password),
        )
        con.commit()
        con.close()
        return True
    except sql.IntegrityError:
        con.close()
        return False


def getName(email):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    cur.execute("SELECT name FROM users WHERE email = ?", (email,))
    data = cur.fetchone()
    if data is None:
        con.close()
        return None
    data = data[0]
    con.close()
    return data


def getLogs(search_term=None, filter_by=None, sort_by="entry_time", sort_order="DESC"):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    valid_sort_columns = [
        "entry_time",
        "start_time",
        "proj_name",
        "time_worked",
        "name",
    ]
    if sort_by not in valid_sort_columns:
        sort_by = "entry_time"
    valid_sort_orders = ["ASC", "DESC"]
    if sort_order not in valid_sort_orders:
        sort_order = "DESC"
    query = "SELECT id, name, proj_name, start_time, end_time, entry_time, time_worked, repo, notes FROM devlogs"
    params = []

    where_clauses = []

    if search_term:
        where_clauses.append("(notes LIKE ? or proj_name LIKE ? OR name LIKE ?)")
        search_pattern = f"%{search_term}%"
        params.extend([search_pattern, search_pattern, search_pattern])

    if filter_by:
        where_clauses.append("DATE(start_time) = ?")
        params.append(filter_by)

    if where_clauses:
        query += " WHERE " + " AND ".join(where_clauses)

    query += f" ORDER BY {sort_by} {sort_order}"
    cur.execute(query, tuple(params))
    data = cur.fetchall()
    con.close()
    cnv_data = []
    for entry in data:
        cnv_entry = list(entry)
        for i in [3, 4, 5]:
            if cnv_entry[i]:
                try:
                    cnv_entry[i] = datetime.datetime.fromisoformat(cnv_entry[i])
                except (ValueError, AttributeError):
                    cnv_entry[i] = None
        cnv_data.append(tuple(cnv_entry))
    return cnv_data


def addLogs(
    email, name, proj_name, start_time, end_time, entry_time, time_worked, repo, notes
):
    con = sql.connect("databaseFiles/database.db")
    cur = con.cursor()
    cur.execute(
        "INSERT INTO devlogs (email, name, proj_name, start_time, end_time, entry_time, time_worked, repo, notes) VALUES (?,?,?,?,?,?,?,?,?)",
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
