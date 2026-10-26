import sqlite3
from pathlib import Path

DB_PATH = Path("D:/vulnscope-data/raw/CVEfixes.db")


def main():
    if not DB_PATH.exists():
        print(f"Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]

    for table in tables:
        cursor.execute(f"PRAGMA table_info({table});")
        columns = [row[1] for row in cursor.fetchall()]
        cursor.execute(f"SELECT COUNT(*) FROM {table};")
        row_count = cursor.fetchone()[0]
        print(f"\nTable: {table}")
        print(f"Rows: {row_count}")
        print(f"Columns: {columns}")

    conn.close()


if __name__ == "__main__":
    main()