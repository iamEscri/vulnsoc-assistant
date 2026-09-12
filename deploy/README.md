# Despliegue de VulnSOC · Vulnerability Intelligence

Requisitos: Docker Engine y Compose, dominio apuntando al VPS, TCP 80 y 443 disponibles. El puerto HTTPS es **443**, no 433. El VPS de 4 CPU y 8 GB dispone de margen para esta configuración inicial; medir carga antes de aumentar los límites.

## Ejecutar en local

Desde la raíz:

```bash
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.lock
.venv/bin/uvicorn backend.app:app --host 127.0.0.1 --port 8010
```

En otra terminal:

```bash
npm ci --prefix frontend
npm run dev --prefix frontend
```

Abre http://127.0.0.1:5173. El frontend reenvía `/api` al puerto 8010. Documentación de API: http://127.0.0.1:8010/api/docs. Node 22 LTS recomendado. El frontend está compilado y tipado con TypeScript; no requiere Node en producción.

## Publicar en el VPS

Configura `.env` a partir de `.env.example`. Nunca subas claves al repositorio.

```env
DOMAIN=tu-dominio.example
IA_PROVIDER=groq
GROQ_API_KEY=tu-clave
GROQ_MODEL=openai/gpt-oss-120b
AI_DAILY_LIMIT=80
AI_VISITOR_DAILY_LIMIT=10
NVD_API_KEY=
GITHUB_TOKEN=
```

`NVD_API_KEY` es opcional. El buscador CPE espacia sus consultas a NVD; el análisis individual conserva el cliente de ingesta original. La búsqueda SigmaHQ original puede no estar disponible sin autenticación; se conserva su alternativa mediante IA. La imagen incluye Groq; los adaptadores históricos Gemini/OpenAI requieren sus SDK adicionales y modelos vigentes si se decide activarlos.

```bash
docker compose up -d --build
docker compose ps
docker compose logs --tail 100
```

Caddy sirve la interfaz y solicita/renueva el certificado. Solo publica 80 y 443. La API no publica puertos al host. El proxy tiene una IP interna fija; Uvicorn confía exclusivamente en esa dirección para la IP del visitante. Si la subred `172.29.0.0/24` ya está ocupada, modifica la subred, la IP de Caddy y `--forwarded-allow-ips` juntos. Si introduces otro proxy/CDN, configura su cadena de confianza antes de confiar en cabeceras adicionales.

La configuración usa un proceso API, caché acotada y SQLite para cuotas/caché operativas. No guarda historiales ni inventarios de usuarios en el servidor. El historial y el inventario permanecen en IndexedDB del navegador; el inventario se envía al backend al analizar para calcular el contexto. La caché de IA incluye el contexto de scoring. Las cuotas son ventanas de 24 horas desde la primera petición, no un reinicio a medianoche. Peticiones a fuentes e IA se coordinan en un proceso para limitar duplicados; para varios servidores habrá que externalizar esta coordinación.

Mantén el volumen `app_data` para conservar cuotas entre reinicios. Respaldar `caddy_data` conserva certificados; exportar JSON desde la interfaz respalda los datos de cada navegador. El cambio de dominio, protocolo o puerto cambia el origen de IndexedDB: exporta antes de migrar URL. No se sincronizan datos entre dispositivos.

## Comprobación

```bash
npm run build --prefix frontend
npm test --prefix frontend
.venv/bin/python -m unittest discover -s tests -v
npx --prefix frontend playwright install chromium
npx --prefix frontend playwright test --config frontend/playwright.config.ts
docker compose config --quiet
```

El servidor Vite debe estar en ejecución para las pruebas Playwright. Puedes indicar un Chromium existente con `PLAYWRIGHT_CHROMIUM_EXECUTABLE`. Las pruebas de navegador simulan las APIs: verifican interfaz, recuperación tras recargar, importación/exportación, búsqueda CPE, fallos de IA y lotes parciales sin gastar cuota real. Las capturas generadas están en `artifacts/`.

Antes de promocionarlo, comprueba en el VPS el dominio, TLS, conectividad NVD/CISA/EPSS, una generación real con Groq y descarga PDF. El despliegue remoto no se ha ejecutado desde este proyecto. Streamlit sigue disponible como referencia histórica con `streamlit run app.py`; la web 2.0 se inicia mediante las instrucciones anteriores.
