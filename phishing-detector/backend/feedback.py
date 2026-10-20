"""
Local store for user feedback and (opt-in) prediction logs — the raw
material for error analysis and the next retrain.

  data/feedback.sqlite (git-ignored, never leaves the machine)
    feedback     a user said a verdict was wrong (or confirmed it)
    predictions  checks the extension made, ONLY if the user enabled
                 "log checks" in its settings — a log of every URL checked
                 is effectively browsing history, so it is off by default

`python feedback.py export` writes reports/feedback_review.csv: reported
mistakes with the model's verdict, ready to relabel into the dataset.
"""

import csv
import os
import sqlite3
import sys
import threading
from datetime import datetime, timezone

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "feedback.sqlite"))
LABELS = {"false_positive", "false_negative", "confirmed_phishing", "confirmed_safe"}

_lock = threading.Lock()


def _conn(db_path=None):
    con = sqlite3.connect(db_path or DB_PATH, check_same_thread=False)
    con.execute("""CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY, ts TEXT, url TEXT, label TEXT, risk_level TEXT,
        probability REAL, model_version TEXT, source TEXT, note TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS predictions (
        id INTEGER PRIMARY KEY, ts TEXT, url TEXT, risk_level TEXT,
        probability REAL, model_version TEXT, source TEXT)""")
    return con


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def add_feedback(url, label, risk_level=None, probability=None, model_version=None,
                 source=None, note=None, db_path=None) -> int:
    if label not in LABELS:
        raise ValueError(f"label must be one of {sorted(LABELS)}")
    with _lock:
        con = _conn(db_path)
        try:
            cur = con.execute(
                "INSERT INTO feedback (ts, url, label, risk_level, probability, model_version, source, note)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (_now(), url, label, risk_level, probability, model_version, source, (note or "")[:500]))
            con.commit()
            return cur.lastrowid
        finally:
            con.close()


def log_prediction(url, risk_level, probability, model_version, source, db_path=None):
    with _lock:
        con = _conn(db_path)
        try:
            con.execute("INSERT INTO predictions (ts, url, risk_level, probability, model_version, source)"
                        " VALUES (?,?,?,?,?,?)",
                        (_now(), url, risk_level, probability, model_version, source))
            con.commit()
        finally:
            con.close()


def stats(db_path=None) -> dict:
    con = _conn(db_path)
    try:
        by_label = dict(con.execute("SELECT label, COUNT(*) FROM feedback GROUP BY label").fetchall())
        by_risk = dict(con.execute("SELECT risk_level, COUNT(*) FROM predictions GROUP BY risk_level").fetchall())
        return {"feedback": by_label, "logged_predictions": by_risk}
    finally:
        con.close()


def export_review(path, db_path=None) -> int:
    con = _conn(db_path)
    try:
        rows = con.execute("SELECT ts, url, label, risk_level, probability, model_version, source, note"
                           " FROM feedback ORDER BY ts").fetchall()
    finally:
        con.close()
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ts", "url", "label", "risk_level", "probability", "model_version", "source", "note",
                     "suggested_training_label"])
        for r in rows:
            suggested = 0 if r[2] in ("false_positive", "confirmed_safe") else 1
            w.writerow([*r, suggested])
    return len(rows)


if __name__ == "__main__" and sys.argv[1:] == ["export"]:
    out = os.path.join(os.path.dirname(__file__), "..", "reports", "feedback_review.csv")
    print(f"Exported {export_review(out)} feedback rows to {os.path.abspath(out)}")
