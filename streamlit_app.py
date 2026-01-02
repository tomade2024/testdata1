import sqlite3
from pathlib import Path
import streamlit as st

DB_PATH = Path("medical_products.db")

# -----------------------------
# DB helpers
# -----------------------------
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
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

    # Optional: einfache Duplikat-Logik (kannst du anpassen/entfernen)
    # Beispiel: interne Artikelnummer sollte eindeutig sein, wenn gesetzt
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_products_internal_article_number
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

    # Trigger zum updated_at pflegen
    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_products_updated_at
        AFTER UPDATE ON products
        FOR EACH ROW
        BEGIN
            UPDATE products SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
        END;
    """)
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

def upsert_product(conn, product_id, name, manufacturer, man_art_no, udi, gtin, internal_no):
    cur = conn.cursor()
    if product_id is None:
        cur.execute("""
            INSERT INTO products (name, manufacturer, manufacturer_article_number, udi_barcode, gtin, internal_article_number)
            VALUES (?, ?, ?, ?, ?, ?);
        """, (name, manufacturer, man_art_no, udi, gtin, internal_no))
        conn.commit()
        return cur.lastrowid
    else:
        cur.execute("""
            UPDATE products
            SET name = ?, manufacturer = ?, manufacturer_article_number = ?, udi_barcode = ?, gtin = ?, internal_article_number = ?
            WHERE id = ?;
        """, (name, manufacturer, man_art_no, udi, gtin, internal_no, product_id))
        conn.commit()
        return product_id

def set_alternatives(conn, product_id: int, alternative_ids: list[int]):
    cur = conn.cursor()
    # Bestehende löschen
    cur.execute("DELETE FROM product_alternatives WHERE product_id = ?;", (product_id,))
    # Neue setzen
    for alt_id in alternative_ids:
        if alt_id == product_id:
            continue
        cur.execute("""
            INSERT OR IGNORE INTO product_alternatives (product_id, alternative_product_id)
            VALUES (?, ?);
        """, (product_id, alt_id))
    conn.commit()

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

def delete_product(conn, product_id: int):
    cur = conn.cursor()
    cur.execute("DELETE FROM products WHERE id = ?;", (product_id,))
    conn.commit()

# -----------------------------
# UI
# -----------------------------
st.set_page_config(page_title="Medizinprodukte Datenbank", layout="wide")

conn = get_conn()
init_db(conn)

st.title("Datenbank für Medizinische Produkte")

tabs = st.tabs(["➕ Eingabe / Bearbeiten", "🔎 Suche"])

# Cache Produktliste in Session für UX
def get_product_options(rows):
    # Für Auswahlanzeigen: "Name — Hersteller (ID: x)"
    return {f"{r['name']} — {r['manufacturer']} (ID: {r['id']})": r["id"] for r in rows}

# -----------------------------
# Tab 1: Eingabe / Bearbeiten
# -----------------------------
with tabs[0]:
    st.subheader("Produkt erfassen oder bearbeiten")

    all_products = fetch_products(conn)
    options_map = get_product_options(all_products)
    option_labels = ["(Neues Produkt)"] + list(options_map.keys())

    colA, colB = st.columns([1, 2], gap="large")

    with colA:
        selected = st.selectbox("Produkt auswählen", option_labels, index=0)
        if selected == "(Neues Produkt)":
            selected_id = None
        else:
            selected_id = options_map[selected]

    # Form-Defaults
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
        current_alt_ids = {r["id"] for r in current_alts}

    with colB:
        with st.form("product_form", clear_on_submit=False):
            c1, c2 = st.columns(2)
            with c1:
                name = st.text_input("Name *", value=default["name"])
                manufacturer = st.text_input("Herstellerfirma *", value=default["manufacturer"])
                manufacturer_article_number = st.text_input("Artikelnummer des Herstellers", value=default.get("manufacturer_article_number") or "")
            with c2:
                udi_barcode = st.text_input("UDI-Barcode", value=default.get("udi_barcode") or "")
                gtin = st.text_input("GTIN", value=default.get("gtin") or "")
                internal_article_number = st.text_input("Interne Artikelnummer", value=default.get("internal_article_number") or "")

            # Alternatives: multiselect aus allen Produkten (ohne sich selbst)
            refreshed_products = fetch_products(conn)
            alt_options = []
            alt_label_to_id = {}
            for r in refreshed_products:
                if selected_id is not None and r["id"] == selected_id:
                    continue
                lbl = f"{r['name']} — {r['manufacturer']} (ID: {r['id']})"
                alt_options.append(lbl)
                alt_label_to_id[lbl] = r["id"]

            preselected_alt_labels = []
            if selected_id is not None:
                for r in current_alts:
                    preselected_alt_labels.append(f"{r['name']} — {r['manufacturer']} (ID: {r['id']})")

            alternatives_labels = st.multiselect(
                "Alternative Produkte (Mehrfachauswahl möglich)",
                options=alt_options,
                default=[l for l in preselected_alt_labels if l in alt_label_to_id],
                help="Wähle Produkte aus, die als Alternative zu diesem Produkt gelten."
            )

            submitted = st.form_submit_button("Speichern")

        if submitted:
            # Validierung
            if not name.strip() or not manufacturer.strip():
                st.error("Bitte mindestens Name und Herstellerfirma ausfüllen.")
            else:
                try:
                    pid = upsert_product(
                        conn,
                        selected_id,
                        name.strip(),
                        manufacturer.strip(),
                        manufacturer_article_number.strip() or None,
                        udi_barcode.strip() or None,
                        gtin.strip() or None,
                        internal_article_number.strip() or None,
                    )
                    alt_ids = [alt_label_to_id[lbl] for lbl in alternatives_labels]
                    set_alternatives(conn, pid, alt_ids)
                    st.success("Produkt gespeichert.")
                    st.rerun()
                except sqlite3.IntegrityError as e:
                    st.error(f"Speichern fehlgeschlagen (Integrität): {e}")
                except Exception as e:
                    st.error(f"Speichern fehlgeschlagen: {e}")

    if selected_id is not None:
        st.divider()
        colD1, colD2 = st.columns([1, 3])
        with colD1:
            if st.button("🗑️ Produkt löschen", type="secondary"):
                delete_product(conn, selected_id)
                st.success("Produkt gelöscht.")
                st.rerun()
        with colD2:
            alts = fetch_alternatives(conn, selected_id)
            if alts:
                st.write("**Aktuelle Alternativen:**")
                st.write(", ".join([f"{a['name']} ({a['manufacturer']})" for a in alts]))
            else:
                st.info("Keine Alternativen hinterlegt.")

# -----------------------------
# Tab 2: Suche
# -----------------------------
with tabs[1]:
    st.subheader("Produkte suchen")

    q = st.text_input("Suchbegriff", placeholder="z. B. Produktname, Hersteller, GTIN, UDI, Artikelnummer ...")
    results = search_products(conn, q)

    st.write(f"**Treffer:** {len(results)}")

    # Ergebnisliste
    for r in results:
        with st.expander(f"{r['name']} — {r['manufacturer']} (ID: {r['id']})", expanded=False):
            c1, c2, c3 = st.columns(3)
            with c1:
                st.write("**Hersteller-Artikelnummer:**", r["manufacturer_article_number"] or "—")
                st.write("**Interne Artikelnummer:**", r["internal_article_number"] or "—")
            with c2:
                st.write("**UDI-Barcode:**", r["udi_barcode"] or "—")
                st.write("**GTIN:**", r["gtin"] or "—")
            with c3:
                alts = fetch_alternatives(conn, r["id"])
                if alts:
                    st.write("**Alternative Produkte:**")
                    st.write("\n".join([f"- {a['name']} — {a['manufacturer']} (ID: {a['id']})" for a in alts]))
                else:
                    st.write("**Alternative Produkte:** —")
