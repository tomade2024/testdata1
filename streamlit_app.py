import io
import json
import re
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

import pandas as pd
import streamlit as st

DB_PATH = Path("medical_products.db")

# -----------------------------
# Security / Auth (simple, local)
# -----------------------------
def auth_config() -> dict:
    return st.secrets.get("auth", {})

def check_login(username: str, password: str) -> Optional[str]:
    cfg = auth_config()
    if not cfg:
        return None

    if username == cfg.get("admin_user") and password == cfg.get("admin_password"):
        return "admin"
    if username == cfg.get("user_user") and password == cfg.get("user_password"):
        return "user"
    return None

def require_role(min_role: str) -> bool:
    # min_role: "user" or "admin"
    role = st.session_state.get("role")
    if min_role == "user":
        return role in ("user", "admin")
    if min_role == "admin":
        return role == "admin"
    return False


# -----------------------------
# Validation
# -----------------------------
def normalize_digits(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    s = str(s).strip()
    if not s:
        return None
    # allow spaces, hyphens - remove them
    s = re.sub(r"[\s\-]", "", s)
    return s or None

def gtin_check_digit_ok(gtin: str) -> bool:
    """
    Supports EAN-8, UPC-A (12), EAN-13, GTIN-14.
    Algorithm: weighted sum from rightmost excluding check digit (3/1 alternating).
    """
    gtin = normalize_digits(gtin)
    if not gtin or not gtin.isdigit():
        return False
    if len(gtin) not in (8, 12, 13, 14):
        return False

    digits = [int(c) for c in gtin]
    check = digits[-1]
    body = digits[:-1]

    # weights from right to left on body: 3,1,3,1...
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
        return True, None, None  # optional field

    if not gtin_n.isdigit():
        return False, gtin_n, "GTIN darf nur Ziffern enthalten (ggf. Leerzeichen/Bindestriche werden entfernt)."

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
    # keep as-is, but collapse whitespace
    u = re.sub(r"\s+", " ", u)
    return u

def validate_udi(udi: Optional[str]) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    UDI is not one universal format; it depends on issuing agency (GS1, HIBCC, ICCBBA, etc).
    Here: robust minimum checks:
      - printable chars
      - length reasonable
      - optional: if GS1 AIs appear like (01) expect digits after it
    """
    u = normalize_udi(udi)
    if u is None:
        return True, None, None  # optional

    if len(u) < 6:
        return False, u, "UDI wirkt zu kurz."
    if len(u) > 200:
        return False, u, "UDI wirkt zu lang (max 200 Zeichen in dieser App)."

    # restrict to common barcode payload characters (broad but safe)
    # allow letters, digits, common punctuation, parentheses, spaces
    if not re.fullmatch(r"[A-Za-z0-9\-\.\+/=\(\)\[\]\{\} :;,_#@%*&!?\|\\<>\"']+", u):
        return False, u, "UDI enthält ungewöhnliche/unerlaubte Zeichen."

    # Minimal GS1-AI heuristic: (01) followed by 14 digits
    m = re.search(r"\(01\)\s*([0-9]{14})", u)
    if m:
        gtin14 = m.group(1)
        if not gtin_check_digit_ok(gtin14):
            return False, u, "UDI enthält eine (01)-GTIN-14 mit ungültiger Prüfziffer."

    return True, u, None


# -----------------------------
# DB helpers
# -----------------------------
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(conn: sqlite3.Connection):
    cur = conn.cursor()
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

    # Unique indexes for duplicates policy: only if value is set/non-empty.
    # You can remove any of these if your policy is different.
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

    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_products_updated_at
        AFTER UPDATE ON products
        FOR EACH ROW
        BEGIN
            UPDATE products SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
        END;
    """)
    conn.commit()

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
    """
    data keys:
      name, manufacturer, manufacturer_article_number, udi_barcode, gtin, internal_article_number
    """
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

def find_existing_by_unique(conn, gtin: Optional[str], udi: Optional[str], internal_no: Optional[str]) -> Optional[int]:
    """
    If any unique key matches an existing record, return its id.
    Priority: internal_article_number, gtin, udi_barcode
    """
    cur = conn.cursor()
    if internal_no:
        cur.execute("SELECT id FROM products WHERE internal_article_number = ?;", (internal_no,))
        r = cur.fetchone()
        if r:
            return int(r["id"])
    if gtin:
        cur.execute("SELECT id FROM products WHERE gtin = ?;", (gtin,))
        r = cur.fetchone()
        if r:
            return int(r["id"])
    if udi:
        cur.execute("SELECT id FROM products WHERE udi_barcode = ?;", (udi,))
        r = cur.fetchone()
        if r:
            return int(r["id"])
    return None

def export_products_df(conn) -> pd.DataFrame:
    rows = fetch_products(conn)
    df = pd.DataFrame([dict(r) for r in rows])
    # Add alternatives as semicolon-separated IDs (simple, robust)
    alt_map = {}
    for r in rows:
        alts = fetch_alternatives(conn, r["id"])
        alt_map[r["id"]] = ";".join(str(a["id"]) for a in alts) if alts else ""
    if not df.empty:
        df["alternative_product_ids"] = df["id"].map(alt_map)
    return df

def read_audit_df(conn, limit: int = 200) -> pd.DataFrame:
    cur = conn.cursor()
    cur.execute("""
        SELECT id, ts, actor, action, entity, entity_id, meta_json
        FROM audit_log
        ORDER BY id DESC
        LIMIT ?;
    """, (limit,))
    rows = cur.fetchall()
    return pd.DataFrame([dict(r) for r in rows])


# -----------------------------
# Import helpers
# -----------------------------
EXPECTED_COLUMNS = [
    "name",
    "manufacturer",
    "manufacturer_article_number",
    "udi_barcode",
    "gtin",
    "internal_article_number",
    "alternative_product_ids",  # optional: "1;2;3"
]

def coerce_str_or_none(v) -> Optional[str]:
    if pd.isna(v):
        return None
    s = str(v).strip()
    return s if s else None

def parse_alt_ids(s: Optional[str]) -> List[int]:
    if not s:
        return []
    parts = re.split(r"[;, ]+", str(s).strip())
    out = []
    for p in parts:
        if not p:
            continue
        if p.isdigit():
            out.append(int(p))
    return sorted(set(out))

def validate_product_payload(payload: dict) -> Tuple[bool, dict, List[str]]:
    """
    Returns (ok, normalized_payload, errors)
    """
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
# UI
# -----------------------------
st.set_page_config(page_title="Medizinprodukte Datenbank", layout="wide")

conn = get_conn()
init_db(conn)

# ---------- Login UI ----------
with st.sidebar:
    st.header("Zugriff")

    if "role" not in st.session_state:
        st.session_state.role = None
        st.session_state.username = None

    if st.session_state.role is None:
        st.caption("Bitte anmelden (Admin oder User).")
        u = st.text_input("Benutzername", key="login_user")
        p = st.text_input("Passwort", type="password", key="login_pass")

        if st.button("Anmelden"):
            role = check_login(u, p)
            if role:
                st.session_state.role = role
                st.session_state.username = u
                audit(conn, action="LOGIN", entity="auth", meta={"role": role})
                st.success(f"Angemeldet als {role}.")
                st.rerun()
            else:
                audit(conn, action="LOGIN_FAILED", entity="auth", meta={"username": u})
                st.error("Login fehlgeschlagen.")
    else:
        st.write(f"**Benutzer:** {st.session_state.username}")
        st.write(f"**Rolle:** {st.session_state.role}")
        if st.button("Abmelden"):
            audit(conn, action="LOGOUT", entity="auth", meta={"role": st.session_state.role})
            st.session_state.role = None
            st.session_state.username = None
            st.rerun()

st.title("Datenbank für Medizinische Produkte")

if not require_role("user"):
    st.info("Bitte zuerst in der Seitenleiste anmelden.")
    st.stop()

# Tabs (Admin sieht zusätzliche Bereiche)
tab_labels = ["➕ Eingabe / Bearbeiten", "🔎 Suche", "⬇️⬆️ Import/Export"]
if require_role("admin"):
    tab_labels.append("🧾 Audit Trail")

tabs = st.tabs(tab_labels)

# Common options mapping
def product_label(row) -> str:
    return f"{row['name']} — {row['manufacturer']} (ID: {row['id']})"

def options_map(rows) -> Dict[str, int]:
    return {product_label(r): int(r["id"]) for r in rows}

# -----------------------------
# Tab 1: Eingabe / Bearbeiten
# -----------------------------
with tabs[0]:
    st.subheader("Produkt erfassen oder bearbeiten")

    all_products = fetch_products(conn)
    omap = options_map(all_products)
    labels = ["(Neues Produkt)"] + list(omap.keys())

    colA, colB = st.columns([1, 2], gap="large")

    with colA:
        selected = st.selectbox("Produkt auswählen", labels, index=0)
        selected_id = None if selected == "(Neues Produkt)" else omap[selected]
        if selected_id and not require_role("admin"):
            st.info("Hinweis: Als User kannst du Daten ansehen, aber nicht ändern.")

    # load defaults
    if selected_id is None:
        default = {
            "name": "",
            "manufacturer": "",
            "manufacturer_article_number": "",
            "udi_barcode": "",
            "gtin": "",
            "internal_article_number": ""
        }
        current_alts = []
    else:
        row = fetch_product(conn, selected_id)
        default = dict(row) if row else {
            "name": "",
            "manufacturer": "",
            "manufacturer_article_number": "",
            "udi_barcode": "",
            "gtin": "",
            "internal_article_number": ""
        }
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

            # alternatives multiselect
            refreshed = fetch_products(conn)
            alt_options = []
            alt_label_to_id = {}
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
                disabled=disabled,
                help="Viele-zu-viele Zuordnung: ein Produkt kann mehrere Alternativen haben."
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
                    # usually duplicate unique index
                    st.error(f"Speichern fehlgeschlagen (Dubletten/Unique-Regel): {e}")
                except Exception as e:
                    st.error(f"Speichern fehlgeschlagen: {e}")

    if selected_id is not None:
        st.divider()
        c1, c2, c3 = st.columns([1, 2, 2])
        with c1:
            if require_role("admin"):
                if st.button("🗑️ Produkt löschen", type="secondary"):
                    delete_product(conn, selected_id)
                    st.success("Produkt gelöscht.")
                    st.rerun()
            else:
                st.caption("Löschen nur als Admin möglich.")
        with c2:
            alts = fetch_alternatives(conn, selected_id)
            st.write("**Alternative Produkte:**")
            if alts:
                st.write(", ".join([f"{a['name']} ({a['manufacturer']})" for a in alts]))
            else:
                st.write("—")
        with c3:
            st.write("**Hinweise zur Validierung**")
            st.write("- GTIN: Länge 8/12/13/14 und Prüfziffer wird geprüft.")
            st.write("- UDI: syntaktische Checks; bei GS1-AI (01) wird GTIN-14 Prüfziffer geprüft.")

# -----------------------------
# Tab 2: Suche
# -----------------------------
with tabs[1]:
    st.subheader("Produkte suchen")

    q = st.text_input("Suchbegriff", placeholder="z. B. Produktname, Hersteller, GTIN, UDI, Artikelnummer ...")
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
                if alts:
                    st.write("**Alternative Produkte:**")
                    st.write("\n".join([f"- {a['name']} — {a['manufacturer']} (ID: {a['id']})" for a in alts]))
                else:
                    st.write("**Alternative Produkte:** —")

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
        export_format = st.selectbox("Format", ["CSV", "Excel (XLSX)"], index=1)
        if df.empty:
            st.info("Keine Daten zum Export vorhanden.")
        else:
            if export_format == "CSV":
                csv_bytes = df.to_csv(index=False).encode("utf-8")
                st.download_button("CSV herunterladen", data=csv_bytes, file_name="medical_products_export.csv", mime="text/csv")
            else:
                bio = io.BytesIO()
                with pd.ExcelWriter(bio, engine="openpyxl") as writer:
                    df.to_excel(writer, index=False, sheet_name="products")
                st.download_button(
                    "Excel herunterladen",
                    data=bio.getvalue(),
                    file_name="medical_products_export.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )

    with c2:
        st.write("### Import")
        if not require_role("admin"):
            st.info("Import ist nur als Admin möglich.")
        else:
            st.caption("Erwartete Spalten: " + ", ".join(EXPECTED_COLUMNS))
            st.caption("Pflicht: name, manufacturer. Optional: manufacturer_article_number, udi_barcode, gtin, internal_article_number, alternative_product_ids")

            uploaded = st.file_uploader("CSV oder Excel hochladen", type=["csv", "xlsx"])
            import_mode = st.selectbox(
                "Import-Modus",
                [
                    "Upsert (empfohlen): bestehende Datensätze anhand interner Nr/GTIN/UDI aktualisieren, sonst neu anlegen",
                    "Nur neu: bei Dublette Fehler",
                ],
                index=0
            )

            if uploaded is not None:
                try:
                    if uploaded.name.lower().endswith(".csv"):
                        imp = pd.read_csv(uploaded)
                    else:
                        imp = pd.read_excel(uploaded)

                    # Normalize columns
                    imp.columns = [c.strip() for c in imp.columns]
                    missing = [c for c in ["name", "manufacturer"] if c not in imp.columns]
                    if missing:
                        st.error(f"Fehlende Pflicht-Spalten: {missing}")
                    else:
                        st.write("Vorschau:")
                        st.dataframe(imp.head(50), use_container_width=True)

                        if st.button("Import starten"):
                            created, updated, failed = 0, 0, 0
                            errors_out = []

                            for i, row in imp.iterrows():
                                raw = {k: row[k] if k in imp.columns else None for k in EXPECTED_COLUMNS}
                                payload = {
                                    "name": coerce_str_or_none(raw.get("name")) or "",
                                    "manufacturer": coerce_str_or_none(raw.get("manufacturer")) or "",
                                    "manufacturer_article_number": coerce_str_or_none(raw.get("manufacturer_article_number")),
                                    "udi_barcode": coerce_str_or_none(raw.get("udi_barcode")),
                                    "gtin": coerce_str_or_none(raw.get("gtin")),
                                    "internal_article_number": coerce_str_or_none(raw.get("internal_article_number")),
                                }
                                ok, normalized, errs = validate_product_payload(payload)
                                alt_ids = parse_alt_ids(coerce_str_or_none(raw.get("alternative_product_ids")))

                                if not ok:
                                    failed += 1
                                    errors_out.append({"row": int(i), "errors": errs, "payload": payload})
                                    continue

                                try:
                                    existing_id = find_existing_by_unique(
                                        conn,
                                        normalized.get("gtin"),
                                        normalized.get("udi_barcode"),
                                        normalized.get("internal_article_number"),
                                    )

                                    if import_mode.startswith("Nur neu"):
                                        # force insert
                                        before_row = None
                                        new_id = upsert_product(conn, None, normalized)
                                        set_alternatives(conn, new_id, alt_ids)
                                        audit(conn, action="IMPORT_INSERT", entity="product", entity_id=new_id,
                                              before=before_row, after=dict(fetch_product(conn, new_id)),
                                              meta={"row": int(i), "alt_ids": alt_ids})
                                        created += 1
                                    else:
                                        # Upsert
                                        if existing_id is None:
                                            before_row = None
                                            new_id = upsert_product(conn, None, normalized)
                                            set_alternatives(conn, new_id, alt_ids)
                                            audit(conn, action="IMPORT_INSERT", entity="product", entity_id=new_id,
                                                  before=before_row, after=dict(fetch_product(conn, new_id)),
                                                  meta={"row": int(i), "alt_ids": alt_ids})
                                            created += 1
                                        else:
                                            before_row = dict(fetch_product(conn, existing_id))
                                            upsert_product(conn, existing_id, normalized)
                                            set_alternatives(conn, existing_id, alt_ids)
                                            audit(conn, action="IMPORT_UPDATE", entity="product", entity_id=existing_id,
                                                  before=before_row, after=dict(fetch_product(conn, existing_id)),
                                                  meta={"row": int(i), "alt_ids": alt_ids})
                                            updated += 1

                                except sqlite3.IntegrityError as e:
                                    failed += 1
                                    errors_out.append({"row": int(i), "errors": [str(e)], "payload": normalized})
                                except Exception as e:
                                    failed += 1
                                    errors_out.append({"row": int(i), "errors": [str(e)], "payload": normalized})

                            audit(conn, action="IMPORT_SUMMARY", entity="import",
                                  meta={"created": created, "updated": updated, "failed": failed})

                            st.success(f"Import abgeschlossen. Neu: {created}, Aktualisiert: {updated}, Fehler: {failed}")

                            if errors_out:
                                st.write("Fehlerdetails:")
                                st.dataframe(pd.DataFrame(errors_out), use_container_width=True)

                            st.rerun()

                except Exception as e:
                    st.error(f"Datei konnte nicht gelesen werden: {e}")

# -----------------------------
# Tab 4: Audit Trail (Admin)
# -----------------------------
if require_role("admin"):
    with tabs[3]:
        st.subheader("Audit Trail (Admin)")
        limit = st.slider("Anzahl Einträge", min_value=50, max_value=1000, value=200, step=50)
        adf = read_audit_df(conn, limit=limit)
        st.dataframe(adf, use_container_width=True)

        st.caption("Detaildaten (before/after) sind in der DB gespeichert, werden hier aus Lesbarkeitsgründen nicht vollständig gerendert.")
