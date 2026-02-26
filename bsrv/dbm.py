# coding=utf-8
import sqlite3
import base64
from typing import Any

class ProjectDoesntExist(Exception):
    pass

class UserDoesntExist(Exception):
    pass

class UserAlreadyExists(Exception):
    pass

class DBM:
    def __init__(self, db_file: str="db.db", projects_path: str="projects/project_") -> None:
        self.db_file = db_file
        self.projects_path = projects_path
        self.__create_tables()

    def __cursor_and_connection(self) -> tuple[sqlite3.Cursor, sqlite3.Connection]:
        connection = sqlite3.connect(self.db_file)
        return connection.cursor(), connection

    def __write_to_file(self, pid: int, data: bytes):
        with open(self.projects_path + str(pid), "wb+") as f:
            f.write(data)

    def __read_from_file(self, pid: int) -> bytes:
        with open(self.projects_path + str(pid), "rb") as f:
            return f.read()

    def __create_tables(self) -> None:
        cur, conn = self.__cursor_and_connection()
        cur.execute("BEGIN TRANSACTION")
        cur.execute("""CREATE TABLE IF NOT EXISTS projects(
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          name TEXT NOT NULL,
                          description TEXT,
                          author_id INTEGER NOT NULL,
                          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                          is_public BOOLEAN NOT NULL DEFAULT FALSE,
                          FOREIGN KEY(author_id) REFERENCES users(id) ON DELETE CASCADE);""")

        cur.execute("""CREATE TABLE IF NOT EXISTS users(
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          username TEXT NOT NULL UNIQUE,
                          name TEXT NOT NULL,
                          email TEXT NOT NULL,
                          password_hash TEXT NOT NULL,
                          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                          is_admin BOOLEAN NOT NULL DEFAULT FALSE,
                          is_banned BOOLEAN NOT NULL DEFAULT FALSE);""")

        cur.execute("""CREATE TABLE IF NOT EXISTS reactions(
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          type TEXT NOT NULL,
                          user_id INTEGER NOT NULL,
                          project_id INTEGER NOT NULL,
                          UNIQUE(user_id, project_id, type),
                          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                          FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE);""")

        cur.execute("""CREATE TABLE IF NOT EXISTS comments(
                          id INTEGER PRIMARY KEY AUTOINCREMENT,
                          user_id INTEGER NOT NULL,
                          project_id INTEGER NOT NULL,
                          text TEXT NOT NULL,
                          FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                          FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE);""")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_reactions_project_id ON reactions(project_id);")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_reactions_project ON reactions(user_id, project_id);")
        conn.commit()
        conn.close()
    
    def __does_project_exist(self, project_id: int) -> bool:
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("""SELECT * FROM projects WHERE id = ?;""", (project_id,))
            return bool(cur.fetchone())
    
    def __does_user_exist(self, user_id: int) -> bool:
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("""SELECT * FROM users WHERE id = ?;""", (user_id,))
            return bool(cur.fetchone())
    
    def __does_username_exist(self, username: str) -> bool:
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("""SELECT * FROM users WHERE username = ?;""", (username,))
            return bool(cur.fetchone())

    def get_project(self, project_id: int) -> dict[str, Any]:
        if not self.__does_project_exist(project_id):
            raise ProjectDoesntExist
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("""SELECT * FROM projects WHERE id = ?;""", (project_id,))
            result = cur.fetchone()
            cur.execute("""SELECT COUNT(*) FROM reactions
                               WHERE project_id = ? AND type = ?;""", (project_id, "like"))
            likes = cur.fetchone()[0]
            cur.execute("""SELECT COUNT(*) FROM reactions
                               WHERE project_id = ? AND type = ?;""", (project_id, "fav"))
            favorites = cur.fetchone()[0]
            file = base64.encodebytes(self.__read_from_file(project_id))
        return {"id": result[0],
                "name": result[1],
                "description": result[2],
                "author_id": result[3],
                "created_at": result[4],
                "is_public": result[5],
                "likes": likes,
                "favorites": favorites,
                "file": file}

    def get_user(self, user_id: int) -> dict[str, Any]:
        if not self.__does_user_exist(user_id):
            raise UserDoesntExist
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("""SELECT * FROM users WHERE id = ?;""", (user_id,))
            result = cur.fetchone()
        return {"id": result[0],
                "username": result[1],
                "name": result[2],
                "email": result[3],
                "password_hash": result[4],
                "created_at": result[5],
                "is_admin": result[6],
                "is_banned": result[7]}

    def add_project(self, name: str, description: str, author_id: int, file)-> int:
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("BEGIN TRANSACTION")
            cur.execute("INSERT INTO projects(name, description, author_id) VALUES (?, ?, ?) RETURNING id;",
                           (name, description, author_id))
            pid = cur.fetchone()[0]
            try:
                self.__write_to_file(pid, file)
            except Exception as e:
                conn.rollback()
                raise e
            else:
                conn.commit()
        return pid
    
    def add_user(self, username: str, name: str, password_hash: str, email: str)-> int:
        if self.__does_username_exist(username):
            raise UserAlreadyExists
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("BEGIN TRANSACTION")
            cur.execute("INSERT INTO users(username, name, password_hash, email) VALUES (?, ?, ?, ?) RETURNING id;",
                        (username, name, password_hash, email))
            uid = cur.fetchone()[0]
            conn.commit()
        return uid
    
    def get_all_users(self)-> list[dict[str, Any]]:
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("""SELECT * FROM users;""")
            result = cur.fetchall()
        return [{"id": row[0],
                 "username": row[1],
                 "name": row[2],
                 "email": row[3],
                 "created_at": row[5],
                 "is_admin": row[6],
                 "is_banned": row[7]} for row in result]
    
    def get_user_id(self, username: str) -> int:
        if not self.__does_username_exist(username):
            raise UserDoesntExist
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("""SELECT id FROM users WHERE username = ?;""", (username,))
            uid = cur.fetchone()[0]
        return uid
    
    def get_user_psw_by_username(self, username: str) -> str:
        return self.get_user(self.get_user_id(username))["password_hash"]
    
    def edit_password(self, uid: int, new_password: str):
        if not self.__does_user_exist(uid):
            raise UserDoesntExist
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("BEGIN TRANSACTION;")
            cur.execute("UPDATE users SET password_hash = ? WHERE id = ?;", (new_password, uid))
            conn.commit()
    
    def change_user_admin_status(self, uid: int, status: bool):
        if not self.__does_user_exist(uid):
            raise UserDoesntExist
        cur, conn = self.__cursor_and_connection()
        with conn:
            cur.execute("BEGIN TRANSACTION;")
            cur.execute("UPDATE users SET is_admin = ? WHERE id = ?;", (status, uid))
            conn.commit()
