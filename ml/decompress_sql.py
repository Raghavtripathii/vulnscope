import gzip
import shutil
from pathlib import Path

SOURCE = Path("D:/vulnscope-data/raw/CVEfixes_v1.0.8.sql.gz")
DEST = Path("D:/vulnscope-data/raw/CVEfixes_v1.0.8.sql")


def main():
    if not SOURCE.exists():
        print(f"File not found at {SOURCE}")
        return

    print("Decompressing, this can take a while for a large file...")
    with gzip.open(SOURCE, "rb") as f_in, open(DEST, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out, length=1024 * 1024 * 16)

    print(f"Done. Wrote {DEST}")


if __name__ == "__main__":
    main()