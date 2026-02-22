# coding=utf-8
import sqlite3
from typing import Any


class DBM:
    def __init__(self, db_file="db.db") -> None:
        self.db_file = db_file
    
    @property
    def __connect(self) -> sqlite3.Connection:
        with sqlite3.connect(self.db_file) as conn:
            return conn
    
    @property
    def __cursor(self) -> sqlite3.Cursor:
        return sqlite3.Cursor(self.__connect)
    
    def execute(self, sql, data) -> None:
        self.__cursor.execute(sql, data)
    
    def select(self, sql, data) -> list[Any]:
        cursor = self.__cursor
        cursor.execute(sql, data)
        return cursor.fetchall()
