# SOC Casero con Honeypot, IA y RAG

Sistema de detección y análisis de amenazas construido desde cero para aprendizaje de ciberseguridad real.

## Descripción

Este proyecto implementa un SOC (Security Operations Center) doméstico completo que:

- Captura ataques reales de internet mediante un honeypot SSH
- Analiza automáticamente cada ataque con IA (Groq/Llama 3.3 70B)
- Genera reportes detallados con técnicas MITRE ATT&CK
- Indexa los reportes en una base vectorial para consultas en lenguaje natural
- Notifica en tiempo real por Telegram
- Visualiza todo en dashboards de Grafana y Wazuh

## Arquitectura
```
Internet
    ↓
Cowrie (honeypot SSH) — VPS con IP pública
    ↓ WireGuard (cifrado)
n8n — orquestación de workflows
    ↓
Groq API (Llama 3.3 70B) — análisis de ataques
    ↓
Telegram — notificación inmediata
Reportes .md — guardados en servidor local
    ↓
pgvector + Ollama (Mistral) — RAG consultable
Grafana + Wazuh — dashboards y SIEM
```
## Stack tecnológico

| Componente | Tecnología |
|---|---|
| Honeypot | Cowrie 2.9 |
| SIEM | Wazuh 4.9 |
| IDS | Suricata 8.0 |
| Orquestación | n8n (self-hosted) |
| IA análisis | Groq API — Llama 3.3 70B |
| Base vectorial | PostgreSQL + pgvector |
| Embeddings | Ollama — nomic-embed-text |
| LLM local | Ollama — Mistral 7B |
| Dashboards | Grafana |
| Notificaciones | Telegram Bot API |
| Aislamiento red | Docker + iptables |
| VPN | WireGuard |

## Estructura del proyecto

```
soc-honeypot/
├── honeypot/
│   ├── docker-compose.yml       # Cowrie en Docker aislado
│   ├── log-shipper.py           # Detecta sesiones y envía a n8n
│   └── save-report.py           # Recibe y guarda reportes .md
├── soc-rag/
│   ├── ingest.py                # Indexa reportes en pgvector
│   ├── query.py                 # Consultas RAG en lenguaje natural
│   └── rag-watcher.py           # Ingesta automática de reportes nuevos
├── wazuh/
│   └── cowrie_rules.xml         # Reglas Wazuh para eventos Cowrie
├── systemd/
│   ├── honeypot-receiver.service
│   ├── honeypot-shipper.service
│   ├── rag-watcher.service
│   └── cowrie-shipper.service
├── grafana/
│   └── dashboard.json
├── .env.example
└── README.md
```

## Instalación rápida

### Requisitos

- Ubuntu Server 22.04+
- Docker + Docker Compose
- Python 3.10+
- PostgreSQL 16 con extensión pgvector
- Ollama con modelos `mistral` y `nomic-embed-text`
- VPS con IP pública (para exponer el honeypot)
- WireGuard entre servidor local y VPS

### 1. Clonar el repositorio

```bash
git clone https://github.com/tuusuario/soc-honeypot.git
cd soc-honeypot
```

### 2. Configurar variables de entorno

```bash
cp .env.example honeypot/.env
nano honeypot/.env
# Rellena con tus credenciales reales
```

### 3. Levantar el honeypot

```bash
cd honeypot
docker compose up -d
```

### 4. Instalar servicios systemd

```bash
sudo cp systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable honeypot-receiver honeypot-shipper rag-watcher
sudo systemctl start honeypot-receiver honeypot-shipper rag-watcher
```

### 5. Instalar dependencias Python

```bash
cd soc-rag
python3 -m venv venv
source venv/bin/activate
pip install chromadb ollama psycopg2-binary requests watchdog
```

## Seguridad

- El honeypot está aislado en una red Docker dedicada (`honeypot-net`)
- Reglas iptables bloquean que el honeypot acceda a la LAN interna
- Todo el tráfico de logs viaja cifrado por WireGuard
- Los secretos nunca se suben al repositorio (usar `.env`)

## Ejemplo de reporte generado

```markdown
# Informe de Análisis de Sesión Capturada por Honeypot SSH

## Resumen ejecutivo
Se detectó una sesión de ataque exitosa con login root/admin.
El atacante ejecutó comandos de reconocimiento y descargó malware.

## Técnicas MITRE ATT&CK
- T1110.001: Brute Force — Password Guessing
- T1082: System Information Discovery
- T1105: Ingress Tool Transfer

## Nivel de riesgo: ALTO

## IoCs
- IP: 185.220.101.47 (Tor exit node)
- URL: http://malicious.example.com/payload.sh
```

## Dashboard Grafana

El dashboard incluye:
- Top IPs atacantes
- Distribución por nivel de riesgo
- Mapa geográfico de ataques
- Timeline de sesiones
- Últimas sesiones detectadas

## Consultas RAG

```bash
python3 query.py "¿qué ataques hemos visto esta semana?"
python3 query.py "¿el atacante intentó persistencia?"
python3 query.py "¿cuál fue el ataque más peligroso?"
```

## Licencia

MIT License — libre para uso educativo y personal.

## Disclaimer

Este proyecto es para **fines educativos**. Úsalo responsablemente.
El honeypot captura ataques reales — asegúrate de tener el aislamiento
de red correctamente configurado antes de exponerlo a internet.
