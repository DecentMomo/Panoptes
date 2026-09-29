def find_user(cursor, name: str) -> None:
    statement = "SELECT * FROM users WHERE name = '%s'" % name
    cursor.execute(statement)
