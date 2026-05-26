#!/usr/bin/env python3
import ollama
import psycopg2
import sys

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

def query_rag(pregunta: str, n_resultados: int = 3):
    embedding = get_embedding(pregunta)
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    cur.execute("""
        SELECT content, filename, src_ip, risk_level, attack_type,
               1 - (embedding <=> %s::vector) AS similarity
        FROM soc_reports
        ORDER BY embedding <=> %s::vector
        LIMIT %s
    """, (str(embedding), str(embedding), n_resultados))

    resultados = cur.fetchall()
    cur.close()
    conn.close()

    if not resultados:
        return "No encontré reportes similares en la base de datos."

    contexto = ""
    for i, (content, filename, src_ip, risk_level, attack_type, similarity) in enumerate(resultados):
        contexto += f"\n--- Reporte {i+1} (similitud: {similarity:.2f}) ---\n"
        contexto += f"Archivo: {filename} | IP: {src_ip} | Riesgo: {risk_level}\n"
        contexto += f"{content}\n"

    response = client.chat(
        model="mistral",
        messages=[
            {
                "role": "system",
                "content": "Eres un analista SOC. Usa los reportes anteriores como contexto para responder preguntas sobre ataques al honeypot. Sé conciso y técnico."
            },
            {
                "role": "user",
                "content": f"Contexto de reportes anteriores:\n{contexto}\n\nPregunta: {pregunta}"
            }
        ]
    )

    return response["message"]["content"]

if __name__ == "__main__":
    if len(sys.argv) > 1:
        pregunta = " ".join(sys.argv[1:])
    else:
        pregunta = input("🔍 Pregunta: ")

    print("\n💬 Respuesta:\n")
    print(query_rag(pregunta))
