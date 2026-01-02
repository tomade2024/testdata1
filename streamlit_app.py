import io
import json
import re
import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any

import bcrypt
import pandas as pd
import streamlit as st

DB_PATH = Path("medical_products.db")

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin123"  # requested; change after first login


# -----------------------------
# DB
# -----------------------------
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(conn: sqlite3.Connection):
    cur = conn.cursor()

    # Products
    cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            manufacturer TEXT NOT NULL,
            manufacturer_article_number TEXT,
            udi_barcode TEXT,
            gtin TEXT,
            internal_article_number TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_products_gtin_unique
        ON products(gtin)
        WHERE gtin IS NOT NULL AND gtin != '';
    """)
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_products_udi_unique
        ON products(udi_barcode)
        WHERE udi_barcode IS NOT NULL AND udi_barcode != '';
    """)
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_products_internal_unique
        ON products(internal_article_number)
        WHERE internal_article_number IS NOT NULL AND internal_article_number != '';
    """)

    # Alternatives
    cur.execute("""
        CREATE TABLE IF NOT EXISTS product_alternatives (
            product_id INTEGER NOT NULL,
            alternative_product_id INTEGER NOT NULL,
            PRIMARY KEY (product_id, alternative_product_id),
            FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
            FOREIGN KEY (alternative_product_id) REFERENCES products(id) ON DELETE CASCADE,
            CHECK (product_id != alternative_product_id)
        );
    """)

    # Users (bcrypt hashed passwords)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash BLOB NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','user')),
            is_active INTEGER NOT NULL DEFAULT 1,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)

    # Audit
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP,
            actor TEXT,
            action TEXT NOT NULL,
            entity TEXT,
            entity_id INTEGER,
            before_json TEXT,
            after_json TEXT,
            meta_json TEXT
        );
    """)

    # Triggers
    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_products_updated_at
        AFTER UPDATE ON products
        FOR EACH ROW
        BEGIN
            UPDATE products SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
        END;
    """)
    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_users_updated_at
        AFTER UPDATE ON users
        FOR EACH ROW
        BEGIN
            UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
        END;
    """)

    conn.commit()

    # Ensure default admin exists
    ensure_default_admin(conn)


def audit(conn, action: str, entity: str = None, entity_id: int = None,
          before: dict = None, after: dict = None, meta: dict = None):
    actor = st.session_state.get("username") or "anonymous"
    conn.execute("""
        INSERT INTO audit_log (actor, action, entity, entity_id, before_json, after_json, meta_json)
        VALUES (?, ?, ?, ?, ?, ?, ?);
    """, (
        actor, action, entity, entity_id,
        json.dumps(before, ensure_ascii=False) if before else None,
        json.dumps(after, ensure_ascii=False) if after else None,
        json.dumps(meta, ensure_ascii=False) if meta else None
    ))
    conn.commit()


# -----------------------------
# Auth (users table)
# -----------------------------
def hash_password(pw: str) -> bytes:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt())

def verify_password(pw: str, pw_hash: bytes) -> bool:
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), pw_hash)
    except Exception:
        return False

def ensure_default_admin(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username = ?;", (DEFAULT_ADMIN_USERNAME,))
    row = cur.fetchone()
    if row:
        return

    pw_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
    cur.execute("""
        INSERT INTO users (username, password_hash, role, is_active, must_change_password)
        VALUES (?, ?, 'admin', 1, 1);
    """, (DEFAULT_ADMIN_USERNAME, pw_hash))
    conn.commit()

def get_user_by_username(conn, username: str):
    cur = conn.cursor()
    cur.execute("""
        SELECT id, username, password_hash, role, is_active, must_change_password
        FROM users
        WHERE username = ?;
    """, (username,))
    return cur.fetchone()

def login(conn, username: str, password: str) -> bool:
    user = get_user_by_username(conn, username)
    if not user:
        audit(conn, "LOGIN_FAILED", "auth", meta={"username": username, "reason": "not_found"})
        return False
    if int(user["is_active"]) != 1:
        audit(conn, "LOGIN_FAILED", "auth", meta={"username": username, "reason": "inactive"})
        return False
    if not verify_password(password, user["password_hash"]):
        audit(conn, "LOGIN_FAILED", "auth", meta={"username": username, "reason": "bad_password"})
        return False

    st.session_state.user_id = int(user["id"])
    st.session_state.username = user["username"]
    st.session_state.role = user["role"]
    st.session_state.must_change_password = bool(user["must_change_password"])
    audit(conn, "LOGIN", "auth", entity_id=int(user["id"]), meta={"role": user["role"]})
    return True

def logout(conn):
    audit(conn, "LOGOUT", "auth", meta={"role": st.session_state.get("role")})
    for k in ["user_id", "username", "role", "must_change_password"]:
        if k in st.session_state:
            del st.session_state[k]

def require_role(min_role: str) -> bool:
    role = st.session_state.get("role")
    if min_role == "user":
        return role in ("user", "admin")
    if min_role == "admin":
        return role == "admin"
    return False

def set_own_password(conn, user_id: int, new_password: str):
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, is_active, must_change_password FROM users WHERE id = ?;", (user_id,))
    before = cur.fetchone()
    if not before:
        raise ValueError("User not found")

    new_hash = hash_password(new_password)
    cur.execute("""
        UPDATE users
        SET password_hash = ?, must_change_password = 0
        WHERE id = ?;
    """, (new_hash, user_id))
    conn.commit()

    cur.execute("SELECT id, username, role, is_active, must_change_password FROM users WHERE id = ?;", (user_id,))
    after = cur.fetchone()
    audit(conn, "PASSWORD_CHANGE", "user", entity_id=user_id, before=dict(before), after=dict(after))

def admin_create_user(conn, username: str, password: str, role: str):
    if role not in ("admin", "user"):
        raise ValueError("Invalid role")
    cur = conn.cursor()
    pw_hash = hash_password(password)
    cur.execute("""
        INSERT INTO users (username, password_hash, role, is_active, must_change_password)
        VALUES (?, ?, ?, 1, 1);
    """, (username, pw_hash, role))
    conn.commit()
    user_id = cur.lastrowid
    audit(conn, "USER_CREATE", "user", entity_id=user_id, after={"username": username, "role": role, "must_change_password": 1})

def admin_set_user_active(conn, user_id: int, active: bool):
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, is_active, must_change_password FROM users WHERE id = ?;", (user_id,))
    before = cur.fetchone()
    if not before:
        raise ValueError("User not found")
    cur.execute("UPDATE users SET is_active = ? WHERE id = ?;", (1 if active else 0, user_id))
    conn.commit()
    cur.execute("SELECT id, username, role, is_active, must_change_password FROM users WHERE id = ?;", (user_id,))
    after = cur.fetchone()
    audit(conn, "USER_SET_ACTIVE", "user", entity_id=user_id, before=dict(before), after=dict(after))

def admin_reset_password(conn, user_id: int, new_password: str):
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, is_active, must_change_password FROM users WHERE id = ?;", (user_id,))
    before = cur.fetchone()
    if not before:
        raise ValueError("User not found")

    new_hash = hash_password(new_password)
    cur.execute("""
        UPDATE users
        SET password_hash = ?, must_change_password = 1
        WHERE id = ?;
    """, (new_hash, user_id))
    conn.commit()

    cur.execute("SELECT id, username, role, is_active, must_change_password FROM users WHERE id = ?;", (user_id,))
    after = cur.fetchone()
    audit(conn, "USER_RESET_PASSWORD", "user", entity_id=user_id, before=dict(before), after=dict(after))


# -----------------------------
# Validation
# -----------------------------
def normalize_digits(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    s = str(s).strip()
    if not s:
        return None
    s = re.sub(r"[\s\-]", "", s)
    return s or None

def gtin_check_digit_ok(gtin: str) -> bool:
    gtin = normalize_digits(gtin)
    if not gtin or not gtin.isdigit():
        return False
    if len(gtin) not in (8, 12, 13, 14):
        return False
    digits = [int(c) for c in gtin]
    check = digits[-1]
    body = digits[:-1]
    total = 0
    weight = 3
    for d in reversed(body):
        total += d * weight
        weight = 1 if weight == 3 else 3
    calc = (10 - (total % 10)) % 10
    return calc == check

def validate_gtin(gtin: Optional[str]) -> Tuple[bool, Optional[str], Optional[str]]:
    gtin_n = normalize_digits(gtin)
    if gtin_n is None:
        return True, None, None
    if not gtin_n.isdigit():
        return False, gtin_n, "GTIN darf nur Ziffern enthalten (Leerzeichen/Bindestriche werden entfernt)."
    if len(gtin_n) not in (8, 12, 13, 14):
        return False, gtin_n, "GTIN-Länge muss 8, 12, 13 oder 14 Stellen haben."
    if not gtin_check_digit_ok(gtin_n):
        return False, gtin_n, "GTIN-Prüfziffer ist ungültig."
    return True, gtin_n, None

def normalize_udi(udi: Optional[str]) -> Optional[str]:
    if udi is None:
        return None
    u = str(udi).strip()
    if not u:
        return None
    u = re.sub(r"\s+", " ", u)
    return u

def validate_udi(udi: Optional[str]) -> Tuple[bool, Optional[str], Optional[str]]:
    u = normalize_udi(udi)
    if u is None:
        return True, None, None
    if len(u) < 6:
        return False, u, "UDI wirkt zu kurz."
    if len(u) > 200:
        return False, u, "UDI wirkt zu lang (max 200 Zeichen)."
    if not re.fullmatch(r"[A-Za-z0-9\-\.\+/=\(\)\[\]\{\} :;,_#@%*&!?\|\\<>\"']+", u):
        return False, u, "UDI enthält ungewöhnliche/unerlaubte Zeichen."
    m = re.search(r"\(01\)\s*([0-9]{14})", u)
    if m and not gtin_check_digit_ok(m.group(1)):
        return False, u, "UDI enthält eine (01)-GTIN-14 mit ungültiger Prüfziffer."
    return True, u, None

def coerce_str_or_none(v) -> Optional[str]:
    if v is None:
        return None
    if pd.isna(v):
        return None
    s = str(v).strip()
    return s if s else None

def validate_product_payload(payload: dict) -> Tuple[bool, dict, List[str]]:
    errors = []
    name = (payload.get("name") or "").strip()
    manufacturer = (payload.get("manufacturer") or "").strip()
    if not name:
        errors.append("Name fehlt.")
    if not manufacturer:
        errors.append("Herstellerfirma fehlt.")

    ok_gtin, gtin_n, gtin_err = validate_gtin(payload.get("gtin"))
    if not ok_gtin:
        errors.append(gtin_err)

    ok_udi, udi_n, udi_err = validate_udi(payload.get("udi_barcode"))
    if not ok_udi:
        errors.append(udi_err)

    normalized = {
        "name": name,
        "manufacturer": manufacturer,
        "manufacturer_article_number": coerce_str_or_none(payload.get("manufacturer_article_number")),
        "udi_barcode": udi_n,
        "gtin": gtin_n,
        "internal_article_number": coerce_str_or_none(payload.get("internal_article_number")),
    }
    return (len(errors) == 0), normalized, errors


# -----------------------------
# Product DB ops
# -----------------------------
def fetch_products(conn):
    cur = conn.cursor()
    cur.execute("""
        SELECT id, name, manufacturer, manufacturer_article_number, udi_barcode, gtin, internal_article_number
        FROM products
        ORDER BY name COLLATE NOCASE;
    """)
    return cur.fetchall()

def fetch_product(conn, product_id: int):
    cur = conn.cursor()
    cur.execute("""
        SELECT id, name, manufacturer, manufacturer_article_number, udi_barcode, gtin, internal_article_number
        FROM products
        WHERE id = ?;
    """, (product_id,))
    return cur.fetchone()

def fetch_alternatives(conn, product_id: int):
    cur = conn.cursor()
    cur.execute("""
        SELECT p.id, p.name, p.manufacturer
        FROM product_alternatives pa
        JOIN products p ON p.id = pa.alternative_product_id
        WHERE pa.product_id = ?
        ORDER BY p.name COLLATE NOCASE;
    """, (product_id,))
    return cur.fetchall()

def set_alternatives(conn, product_id: int, alternative_ids: list[int]):
    cur = conn.cursor()
    cur.execute("DELETE FROM product_alternatives WHERE product_id = ?;", (product_id,))
    for alt_id in alternative_ids:
        if alt_id == product_id:
            continue
        cur.execute("""
            INSERT OR IGNORE INTO product_alternatives (product_id, alternative_product_id)
            VALUES (?, ?);
        """, (product_id, alt_id))
    conn.commit()

def upsert_product(conn, product_id, data: dict) -> int:
    cur = conn.cursor()
    if product_id is None:
        cur.execute("""
            INSERT INTO products (name, manufacturer, manufacturer_article_number, udi_barcode, gtin, internal_article_number)
            VALUES (?, ?, ?, ?, ?, ?);
        """, (
            data["name"], data["manufacturer"],
            data.get("manufacturer_article_number"),
            data.get("udi_barcode"),
            data.get("gtin"),
            data.get("internal_article_number"),
        ))
        conn.commit()
        return cur.lastrowid
    else:
        cur.execute("""
            UPDATE products
            SET name = ?, manufacturer = ?, manufacturer_article_number = ?, udi_barcode = ?, gtin = ?, internal_article_number = ?
            WHERE id = ?;
        """, (
            data["name"], data["manufacturer"],
            data.get("manufacturer_article_number"),
            data.get("udi_barcode"),
            data.get("gtin"),
            data.get("internal_article_number"),
            product_id
        ))
        conn.commit()
        return product_id

def delete_product(conn, product_id: int):
    row = fetch_product(conn, product_id)
    before = dict(row) if row else None
    conn.execute("DELETE FROM products WHERE id = ?;", (product_id,))
    conn.commit()
    audit(conn, action="DELETE", entity="product", entity_id=product_id, before=before, after=None)

def search_products(conn, q: str):
    q = (q or "").strip()
    if not q:
        return fetch_products(conn)

    like = f"%{q}%"
    cur = conn.cursor()
    cur.execute("""
        SELECT id, name, manufacturer, manufacturer_article_number, udi_barcode, gtin, internal_article_number
        FROM products
        WHERE
            name LIKE ?
            OR manufacturer LIKE ?
            OR manufacturer_article_number LIKE ?
            OR udi_barcode LIKE ?
            OR gtin LIKE ?
            OR internal_article_number LIKE ?
        ORDER BY name COLLATE NOCASE;
    """, (like, like, like, like, like, like))
    return cur.fetchall()

def export_products_df(conn) -> pd.DataFrame:
    rows = fetch_products(conn)
    df = pd.DataFrame([dict(r) for r in rows])
    alt_map = {}
    for r in rows:
        alts = fetch_alternatives(conn, r["id"])
        alt_map[r["id"]] = ";".join(str(a["id"]) for a in alts) if alts else ""
    if not df.empty:
        df["alternative_product_ids"] = df["id"].map(alt_map)
    return df

def parse_alt_ids(s: Optional[str]) -> List[int]:
    if not s:
        return []
    parts = re.split(r"[;, ]+", str(s).strip())
    out = []
    for p in parts:
        if p.isdigit():
            out.append(int(p))
    return sorted(set(out))


# -----------------------------
# UI
# -----------------------------
st.set_page_config(page_title="Medizinprodukte Web-App", layout="wide")
conn = get_conn()
init_db(conn)

# Sidebar login
with st.sidebar:
    st.header("Login")

    if "role" not in st.session_state:
        st.session_state.role = None

    if st.session_state.get("role") is None:
        st.caption("Standard-Admin wird beim ersten Start angelegt.")
        st.write(f"Admin: **{DEFAULT_ADMIN_USERNAME}** / **{DEFAULT_ADMIN_PASSWORD}**")
        u = st.text_input("Benutzername", key="login_user")
        p = st.text_input("Passwort", type="password", key="login_pass")
        if st.button("Anmelden"):
            if login(conn, u, p):
                st.success("Angemeldet.")
                st.rerun()
            else:
                st.error("Login fehlgeschlagen.")
    else:
        st.write(f"**Benutzer:** {st.session_state.get('username')}")
        st.write(f"**Rolle:** {st.session_state.get('role')}")
        if st.button("Abmelden"):
            logout(conn)
            st.rerun()

st.title("Medizinprodukte Datenbank (Web-App)")

if not require_role("user"):
    st.info("Bitte anmelden.")
    st.stop()

# Force password change if flagged
if st.session_state.get("must_change_password"):
    st.warning("Du musst dein Passwort ändern (Standard-Passwort oder Admin-Reset).")
    new1 = st.text_input("Neues Passwort", type="password")
    new2 = st.text_input("Neues Passwort bestätigen", type="password")
    if st.button("Passwort ändern"):
        if len(new1) < 8:
            st.error("Bitte mindestens 8 Zeichen verwenden.")
        elif new1 != new2:
            st.error("Passwörter stimmen nicht überein.")
        else:
            set_own_password(conn, st.session_state["user_id"], new1)
            st.session_state.must_change_password = False
            st.success("Passwort geändert.")
            st.rerun()
    st.stop()

# Tabs
tab_labels = ["➕ Eingabe / Bearbeiten", "🔎 Suche", "⬇️⬆️ Import/Export"]
if require_role("admin"):
    tab_labels += ["👥 Benutzerverwaltung", "🧾 Audit Trail"]
tabs = st.tabs(tab_labels)

def product_label(row) -> str:
    return f"{row['name']} — {row['manufacturer']} (ID: {row['id']})"

# -----------------------------
# Tab 1: Eingabe/Bearbeiten
# -----------------------------
with tabs[0]:
    st.subheader("Produkt erfassen oder bearbeiten")

    all_products = fetch_products(conn)
    omap = {product_label(r): int(r["id"]) for r in all_products}
    labels = ["(Neues Produkt)"] + list(omap.keys())

    colA, colB = st.columns([1, 2], gap="large")
    with colA:
        selected = st.selectbox("Produkt auswählen", labels, index=0)
        selected_id = None if selected == "(Neues Produkt)" else omap[selected]
        if selected_id and not require_role("admin"):
            st.info("Als User kannst du Daten ansehen, aber nicht ändern.")

    if selected_id is None:
        default = {"name": "", "manufacturer": "", "manufacturer_article_number": "", "udi_barcode": "", "gtin": "", "internal_article_number": ""}
        current_alts = []
    else:
        row = fetch_product(conn, selected_id)
        default = dict(row) if row else {"name": "", "manufacturer": "", "manufacturer_article_number": "", "udi_barcode": "", "gtin": "", "internal_article_number": ""}
        current_alts = fetch_alternatives(conn, selected_id)

    with colB:
        disabled = not require_role("admin")
        with st.form("product_form", clear_on_submit=False):
            c1, c2 = st.columns(2)
            with c1:
                name = st.text_input("Name *", value=default.get("name") or "", disabled=disabled)
                manufacturer = st.text_input("Herstellerfirma *", value=default.get("manufacturer") or "", disabled=disabled)
                manufacturer_article_number = st.text_input("Artikelnummer des Herstellers", value=default.get("manufacturer_article_number") or "", disabled=disabled)
            with c2:
                udi_barcode = st.text_input("UDI-Barcode", value=default.get("udi_barcode") or "", disabled=disabled)
                gtin = st.text_input("GTIN", value=default.get("gtin") or "", disabled=disabled)
                internal_article_number = st.text_input("Interne Artikelnummer", value=default.get("internal_article_number") or "", disabled=disabled)

            refreshed = fetch_products(conn)
            alt_label_to_id = {}
            alt_options = []
            for r in refreshed:
                if selected_id is not None and int(r["id"]) == int(selected_id):
                    continue
                lbl = product_label(r)
                alt_options.append(lbl)
                alt_label_to_id[lbl] = int(r["id"])

            preselected = [product_label(a) for a in current_alts] if selected_id else []
            alternatives_labels = st.multiselect(
                "Alternative Produkte (Mehrfachauswahl möglich)",
                options=alt_options,
                default=[l for l in preselected if l in alt_label_to_id],
                disabled=disabled
            )

            submitted = st.form_submit_button("Speichern", disabled=disabled)

        if submitted:
            payload = {
                "name": name,
                "manufacturer": manufacturer,
                "manufacturer_article_number": manufacturer_article_number,
                "udi_barcode": udi_barcode,
                "gtin": gtin,
                "internal_article_number": internal_article_number,
            }
            ok, normalized, errors = validate_product_payload(payload)
            if not ok:
                st.error("Validierung fehlgeschlagen:\n- " + "\n- ".join(errors))
            else:
                try:
                    before_row = dict(fetch_product(conn, selected_id)) if selected_id else None
                    pid = upsert_product(conn, selected_id, normalized)
                    alt_ids = [alt_label_to_id[lbl] for lbl in alternatives_labels]
                    set_alternatives(conn, pid, alt_ids)
                    after_row = dict(fetch_product(conn, pid))
                    audit(conn, action="INSERT" if selected_id is None else "UPDATE",
                          entity="product", entity_id=pid, before=before_row, after=after_row,
                          meta={"alt_ids": alt_ids})
                    st.success("Produkt gespeichert.")
                    st.rerun()
                except sqlite3.IntegrityError as e:
                    st.error(f"Speichern fehlgeschlagen (Dubletten/Unique-Regel): {e}")
                except Exception as e:
                    st.error(f"Speichern fehlgeschlagen: {e}")

    if selected_id is not None:
        st.divider()
        c1, c2 = st.columns([1, 3])
        with c1:
            if require_role("admin"):
                if st.button("🗑️ Produkt löschen", type="secondary"):
                    delete_product(conn, selected_id)
                    st.success("Produkt gelöscht.")
                    st.rerun()
        with c2:
            alts = fetch_alternatives(conn, selected_id)
            st.write("**Alternative Produkte:**")
            if alts:
                st.write(", ".join([f"{a['name']} ({a['manufacturer']})" for a in alts]))
            else:
                st.write("—")

# -----------------------------
# Tab 2: Suche
# -----------------------------
with tabs[1]:
    st.subheader("Produkte suchen")
    q = st.text_input("Suchbegriff", placeholder="Name, Hersteller, GTIN, UDI, Artikelnummer ...")
    results = search_products(conn, q)
    st.write(f"**Treffer:** {len(results)}")

    for r in results:
        with st.expander(f"{r['name']} — {r['manufacturer']} (ID: {r['id']})", expanded=False):
            a1, a2, a3 = st.columns(3)
            with a1:
                st.write("**Hersteller-Artikelnummer:**", r["manufacturer_article_number"] or "—")
                st.write("**Interne Artikelnummer:**", r["internal_article_number"] or "—")
            with a2:
                st.write("**UDI-Barcode:**", r["udi_barcode"] or "—")
                st.write("**GTIN:**", r["gtin"] or "—")
            with a3:
                alts = fetch_alternatives(conn, r["id"])
                st.write("**Alternative Produkte:**")
                if alts:
                    st.write("\n".join([f"- {a['name']} — {a['manufacturer']} (ID: {a['id']})" for a in alts]))
                else:
                    st.write("—")

# -----------------------------
# Tab 3: Import/Export
# -----------------------------
with tabs[2]:
    st.subheader("Import / Export")

    df = export_products_df(conn)
    st.caption("Export enthält zusätzlich `alternative_product_ids` als Semikolon-separierte IDs (z. B. `12;34`).")

    c1, c2 = st.columns(2)
    with c1:
        st.write("### Export")
        fmt = st.selectbox("Format", ["CSV", "Excel (XLSX)"], index=1)
        if df.empty:
            st.info("Keine Daten vorhanden.")
        else:
            if fmt == "CSV":
                st.download_button("CSV herunterladen", df.to_csv(index=False).encode("utf-8"),
                                   file_name="medical_products_export.csv", mime="text/csv")
            else:
                bio = io.BytesIO()
                with pd.ExcelWriter(bio, engine="openpyxl") as writer:
                    df.to_excel(writer, index=False, sheet_name="products")
                st.download_button("Excel herunterladen", bio.getvalue(),
                                   file_name="medical_products_export.xlsx",
                                   mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

    with c2:
        st.write("### Import")
        if not require_role("admin"):
            st.info("Import nur als Admin.")
        else:
            uploaded = st.file_uploader("CSV oder Excel hochladen", type=["csv", "xlsx"])
            mode = st.selectbox("Modus", ["Upsert (empfohlen)", "Nur neu (Fehler bei Dublette)"], index=0)

            if uploaded is not None:
                try:
                    imp = pd.read_csv(uploaded) if uploaded.name.lower().endswith(".csv") else pd.read_excel(uploaded)
                    imp.columns = [c.strip() for c in imp.columns]
                    st.dataframe(imp.head(50), use_container_width=True)

                    if st.button("Import starten"):
                        created = updated = failed = 0
                        errors_out = []

                        for i, row in imp.iterrows():
                            payload = {
                                "name": coerce_str_or_none(row.get("name")) or "",
                                "manufacturer": coerce_str_or_none(row.get("manufacturer")) or "",
                                "manufacturer_article_number": coerce_str_or_none(row.get("manufacturer_article_number")),
                                "udi_barcode": coerce_str_or_none(row.get("udi_barcode")),
                                "gtin": coerce_str_or_none(row.get("gtin")),
                                "internal_article_number": coerce_str_or_none(row.get("internal_article_number")),
                            }
                            alt_ids = parse_alt_ids(coerce_str_or_none(row.get("alternative_product_ids")))

                            ok, normalized, errs = validate_product_payload(payload)
                            if not ok:
                                failed += 1
                                errors_out.append({"row": int(i), "errors": errs, "payload": payload})
                                continue

                            try:
                                if mode.startswith("Nur neu"):
                                    before = None
                                    new_id = upsert_product(conn, None, normalized)
                                    set_alternatives(conn, new_id, alt_ids)
                                    audit(conn, "IMPORT_INSERT", "product", new_id, before, dict(fetch_product(conn, new_id)), {"row": int(i)})
                                    created += 1
                                else:
                                    # Upsert by unique keys handled by DB uniqueness; for simplicity, try insert then update on conflict.
                                    # We'll do: attempt insert, if IntegrityError -> find by unique key and update.
                                    try:
                                        before = None
                                        new_id = upsert_product(conn, None, normalized)
                                        set_alternatives(conn, new_id, alt_ids)
                                        audit(conn, "IMPORT_INSERT", "product", new_id, before, dict(fetch_product(conn, new_id)), {"row": int(i)})
                                        created += 1
                                    except sqlite3.IntegrityError:
                                        # find existing by unique columns
                                        cur = conn.cursor()
                                        existing_id = None
                                        if normalized.get("internal_article_number"):
                                            cur.execute("SELECT id FROM products WHERE internal_article_number = ?;", (normalized["internal_article_number"],))
                                            r = cur.fetchone()
                                            if r: existing_id = int(r["id"])
                                        if existing_id is None and normalized.get("gtin"):
                                            cur.execute("SELECT id FROM products WHERE gtin = ?;", (normalized["gtin"],))
                                            r = cur.fetchone()
                                            if r: existing_id = int(r["id"])
                                        if existing_id is None and normalized.get("udi_barcode"):
                                            cur.execute("SELECT id FROM products WHERE udi_barcode = ?;", (normalized["udi_barcode"],))
                                            r = cur.fetchone()
                                            if r: existing_id = int(r["id"])

                                        if existing_id is None:
                                            raise  # unexpected

                                        before = dict(fetch_product(conn, existing_id))
                                        upsert_product(conn, existing_id, normalized)
                                        set_alternatives(conn, existing_id, alt_ids)
                                        audit(conn, "IMPORT_UPDATE", "product", existing_id, before, dict(fetch_product(conn, existing_id)), {"row": int(i)})
                                        updated += 1

                            except Exception as e:
                                failed += 1
                                errors_out.append({"row": int(i), "errors": [str(e)], "payload": normalized})

                        audit(conn, "IMPORT_SUMMARY", "import", meta={"created": created, "updated": updated, "failed": failed})
                        st.success(f"Import fertig. Neu: {created}, Update: {updated}, Fehler: {failed}")
                        if errors_out:
                            st.dataframe(pd.DataFrame(errors_out), use_container_width=True)
                        st.rerun()

                except Exception as e:
                    st.error(f"Import-Datei konnte nicht gelesen werden: {e}")

# -----------------------------
# Admin: User management
# -----------------------------
if require_role("admin"):
    with tabs[3]:
        st.subheader("Benutzerverwaltung (Admin)")

        cur = conn.cursor()
        cur.execute("SELECT id, username, role, is_active, must_change_password, created_at, updated_at FROM users ORDER BY username;")
        users = cur.fetchall()
        udf = pd.DataFrame([dict(u) for u in users])
        st.dataframe(udf, use_container_width=True)

        st.divider()
        st.write("### Benutzer anlegen")
        with st.form("create_user"):
            nu = st.text_input("Username")
            npw = st.text_input("Initiales Passwort", type="password")
            nrole = st.selectbox("Rolle", ["user", "admin"], index=0)
            create = st.form_submit_button("Anlegen")
        if create:
            if not nu.strip() or not npw:
                st.error("Username und Passwort sind erforderlich.")
            elif len(npw) < 8:
                st.error("Bitte mindestens 8 Zeichen Passwortlänge.")
            else:
                try:
                    admin_create_user(conn, nu.strip(), npw, nrole)
                    st.success("Benutzer angelegt (muss beim ersten Login Passwort ändern).")
                    st.rerun()
                except sqlite3.IntegrityError:
                    st.error("Username existiert bereits.")
                except Exception as e:
                    st.error(str(e))

        st.divider()
        st.write("### Benutzer aktivieren/deaktivieren / Passwort zurücksetzen")
        user_map = {f"{u['username']} (ID {u['id']}, {u['role']})": int(u["id"]) for u in users}
        sel = st.selectbox("Benutzer auswählen", list(user_map.keys()))
        sel_id = user_map[sel]

        cA, cB = st.columns(2)
        with cA:
            active = st.checkbox("Aktiv", value=bool(int([u for u in users if int(u["id"]) == sel_id][0]["is_active"])))
            if st.button("Aktiv-Status speichern"):
                try:
                    admin_set_user_active(conn, sel_id, active)
                    st.success("Status aktualisiert.")
                    st.rerun()
                except Exception as e:
                    st.error(str(e))

        with cB:
            rp = st.text_input("Neues Passwort setzen", type="password")
            if st.button("Passwort zurücksetzen (User muss ändern)"):
                if len(rp) < 8:
                    st.error("Bitte mindestens 8 Zeichen.")
                else:
                    try:
                        admin_reset_password(conn, sel_id, rp)
                        st.success("Passwort zurückgesetzt.")
                        st.rerun()
                    except Exception as e:
                        st.error(str(e))

# -----------------------------
# Admin: Audit trail
# -----------------------------
if require_role("admin"):
    with tabs[4]:
        st.subheader("Audit Trail (Admin)")
        limit = st.slider("Anzahl Einträge", min_value=50, max_value=2000, value=200, step=50)
        cur = conn.cursor()
        cur.execute("""
            SELECT id, ts, actor, action, entity, entity_id, meta_json
            FROM audit_log
            ORDER BY id DESC
            LIMIT ?;
        """, (limit,))
        adf = pd.DataFrame([dict(r) for r in cur.fetchall()])
        st.dataframe(adf, use_container_width=True)
        st.caption("before_json/after_json sind in der DB vorhanden; Meta wird hier kompakt angezeigt.")
