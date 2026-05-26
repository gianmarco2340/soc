#!/usr/bin/env python3
import ollama
import psycopg2
import hashlib
import re
from pathlib import Path

REPORTS_DIR = Path("/home/hyper/honeypot/reportes")
DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "cvedb",
    "user": "YOUR_POSTGRES_USER",
    "password": "YOUR_POSTGRES_PASSWORD"
}

client = ollama.Client()

def get_embedding(text: str) -> list:
    response = client.embeddings(model="nomic-embed-text", prompt=text)
    return response["embedding"]

def extract_metadata(text: str) -> dict:
    # IP atacante en múltiples formatos
    ip_match = re.search(
        r'(?:IP atacante|ip atacante)[^\d]*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})',
        text, re.IGNORECASE
    )
    # Nivel de riesgo
    risk_match = re.search(
        r'(?:riesgo[^*\n]*\*\*|considera[^*\n]*\*\*|riesgo es[^*\n]*\*\*)([^*]+)\*\*|'
        r'nivel de riesgo[^\n]*\n+([A-Za-záéíóú]+)',
        text, re.IGNORECASE
    )
    # Clasificación
    attack_match = re.search(
        r'Clasificación del ataque\s*\n+(.+?)(?:\n|$)',
        text, re.IGNORECASE
    )

    risk = None
    if risk_match:
        risk = (risk_match.group(1) or risk_match.group(2) or "").strip()[:20]

    return {
        "src_ip": ip_match.group(1) if ip_match else None,
        "risk_level": risk,
        "attack_type": attack_match.group(1).strip()[:100] if attack_match else None
    }

def ingest_report(md_path: Path, conn):
    text = md_path.read_text(encoding="utf-8")
    if not text.strip():
        print(f"  ⚠ Vacío: {md_path.name}")
        return 0

    metadata = extract_metadata(text)
    chunks = [c.strip() for c in text.split("##") if len(c.strip()) > 30]
    if not chunks:
        chunks = [text]

    cur = conn.cursor()
    ingested = 0

    for i, chunk in enumerate(chunks):
        # filename + chunk_index como clave única
        unique_key = f"{md_path.name}_{i}"
        doc_id = hashlib.md5(unique_key.encode()).hexdigest()

        # Verificar si ya existe
        cur.execute(
            "SELECT id FROM soc_reports WHERE filename = %s AND chunk_index = %s",
            (md_path.name, i)
        )
        if cur.fetchone():
            continue

        embedding = get_embedding(chunk)

        cur.execute("""
            INSERT INTO soc_reports 
                (filename, src_ip, session_id, risk_level, attack_type, content, chunk_index, embedding)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (filename) DO NOTHING
        """, (
            f"{md_path.stem}_chunk{i}",
            metadata["src_ip"],
            md_path.stem,
            metadata["risk_level"],
            metadata["attack_type"],
            chunk,
            i,
            str(embedding)
        ))
        ingested += 1

    conn.commit()
    cur.close()

    if ingested > 0:
        print(f"  ✓ {md_path.name} — {ingested} chunks")
    return ingested

def main():
    reports = list(REPORTS_DIR.glob("*.md"))
    if not reports:
        print("No hay reportes en", REPORTS_DIR)
        return

    print(f"📚 Indexando {len(reports)} reportes...")
    conn = psycopg2.connect(**DB_CONFIG)

    total = 0
    for report in sorted(reports):
        total += ingest_report(report, conn)

    conn.close()
    print(f"\n✅ Total chunks indexados: {total}")

if __name__ == "__main__":
    main()
