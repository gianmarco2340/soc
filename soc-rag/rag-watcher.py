#!/usr/bin/env python3
import time
import subprocess
from pathlib import Path
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

REPORTS_DIR = Path("/home/hyper/honeypot/reportes")
INGEST_SCRIPT = Path("/home/hyper/soc-rag/ingest.py")
PYTHON = Path("/home/hyper/soc-rag/venv/bin/python3")

class ReportHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix == ".md" and path.stat().st_size > 0:
            print(f"📥 Nuevo reporte detectado: {path.name}")
            time.sleep(2)  # espera a que termine de escribirse
            result = subprocess.run(
                [str(PYTHON), str(INGEST_SCRIPT)],
                capture_output=True, text=True
            )
            print(result.stdout)
            if result.returncode == 0:
                print(f"✅ Indexado correctamente")
            else:
                print(f"❌ Error: {result.stderr}")

if __name__ == "__main__":
    print(f"👁 Vigilando {REPORTS_DIR} para nuevos reportes...")
    observer = Observer()
    observer.schedule(ReportHandler(), str(REPORTS_DIR), recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

