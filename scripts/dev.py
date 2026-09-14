"""Start both local services; stop both when either exits or on Ctrl+C."""
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
python = ROOT / '.venv/bin/python'
if not python.exists() or not shutil.which('npm') or not (ROOT/'frontend/node_modules').exists():
    sys.exit('Instala las dependencias siguiendo deploy/README.md antes de iniciar.')
processes = []
exit_code = 0
try:
    processes.append(subprocess.Popen([str(python), '-m', 'uvicorn', 'backend.app:app', '--host', '127.0.0.1', '--port', '8010'], cwd=ROOT))
    # Use the Vite executable directly so termination reaches the server process.
    processes.append(subprocess.Popen(['node', 'node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', '5173', '--strictPort'], cwd=ROOT/'frontend'))
    print('VulnSOC: http://127.0.0.1:5173 · Ctrl+C detiene web y API.', flush=True)
    while all(p.poll() is None for p in processes):
        time.sleep(.5)
    exit_code = next((p.returncode for p in processes if p.returncode), 0)
except KeyboardInterrupt:
    pass
finally:
    for p in processes:
        if p.poll() is None:
            p.terminate()
    for p in processes:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()

sys.exit(exit_code)
