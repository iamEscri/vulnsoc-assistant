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

Con las dependencias instaladas, puedes iniciar **web y API juntas** desde la raíz:

```bash
python3 scripts/dev.py
```

Mantén esa terminal abierta. `Ctrl+C` detiene ambos servicios. No ejecutes simultáneamente este comando y los arranques individuales anteriores.

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

`NVD_API_KEY` es opcional. El buscador CPE espacia sus consultas a NVD; el análisis individual y la búsqueda comparten el cliente de consultas espaciadas y la selección CVSS. La búsqueda SigmaHQ original puede no estar disponible sin autenticación; se conserva su alternativa mediante IA. La imagen incluye Groq; los adaptadores históricos Gemini/OpenAI requieren sus SDK adicionales y modelos vigentes si se decide activarlos.

```bash
docker compose up -d --build
docker compose ps
docker compose logs --tail 100
```

Caddy sirve la interfaz y solicita/renueva el certificado. Solo publica 80 y 443. La API no publica puertos al host. El proxy tiene una IP interna fija; Uvicorn confía exclusivamente en esa dirección para la IP del visitante. Si la subred `172.29.0.0/24` ya está ocupada, modifica la subred, la IP de Caddy y `--forwarded-allow-ips` juntos. Si introduces otro proxy/CDN, configura su cadena de confianza antes de confiar en cabeceras adicionales.

La configuración usa un proceso API, caché acotada y SQLite para cuotas/caché operativas. No guarda historiales ni inventarios de usuarios en el servidor. El historial y el inventario permanecen en IndexedDB del navegador; el inventario se envía al backend al analizar para calcular el contexto. La caché de IA incluye el contexto de scoring. Las cuotas son ventanas de 24 horas desde la primera petición, no un reinicio a medianoche. Peticiones a fuentes e IA se coordinan en un proceso para limitar duplicados; para varios servidores habrá que externalizar esta coordinación.

Mantén el volumen `app_data` para conservar cuotas entre reinicios. Respaldar `caddy_data` conserva certificados; exportar JSON desde la interfaz respalda los datos de cada navegador. El cambio de dominio, protocolo o puerto cambia el origen de IndexedDB: exporta antes de migrar URL. No se sincronizan datos entre dispositivos.

## Comprobación

### Conflicto de IP durante el primer arranque

La web usa `172.29.0.2` y la API `172.29.0.3`. Ambas direcciones son explícitas para evitar que la API, que arranca primero, reciba automáticamente la dirección del proxy. Si se desplegó la configuración anterior y aparece `failed to set up container networking: Address already in use`, actualiza y recrea los contenedores y la red:

```bash
git pull --ff-only origin main
sudo docker compose down
sudo docker compose up -d --build
sudo docker compose ps
```

No añadas `-v` a `down`: los volúmenes conservan certificados y estado operativo. Si cambias la subred, actualiza ambas IP y la dirección del proxy de confianza en `deploy/Dockerfile.api`.

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

## Ejemplos preanalizados

La home incluye Log4Shell y Terrapin consultados el 13/09/2026 a través de NVD, CISA KEV y FIRST EPSS, con el motor real y sin inventario. Las instantáneas están en `frontend/src/examples/`. Son material explicativo fechado, no datos actuales ni análisis del entorno del visitante. Seleccionarlos no modifica el historial. «Analizar con datos actuales» consulta la API y guarda el resultado como cualquier otro análisis.

Para actualizarlos, usa `/api/analyze` sin inventario ni IA, comprueba que ninguna fuente devuelve error y sustituye la instantánea completa conservando su `fecha`. No edites a mano factores o puntuaciones.

## Verificación histórica del 13/09/2026 (política anterior)

- Consultas reales de Log4Shell y Terrapin: NVD, KEV y EPSS disponibles; 225 y 119 puntos respectivamente, sin inventario.
- Búsqueda real CPE de Tomcat 9.0.80: un producto; búsqueda de vulnerabilidades: 59 resultados, primera página de 20.
- Generación real de las tres secciones de IA con Groq y exportación de PDF con contenido extraíble.
- Sigma: se corrigió la aceptación de respuestas vacías. La generación real devuelve un borrador experimental descargable; su eficacia de detección no se ha validado.
- Prueba Playwright real de análisis, IA, Sigma y descarga PDF. Para repetirla con API y claves configuradas (consume cuota):

```bash
VULNSOC_LIVE=1 npx --prefix frontend playwright test --config frontend/playwright.config.ts live.spec.ts
```

La suite normal omite esta prueba externa. Las instantáneas de ejemplo no sustituyen una consulta actual. Estas comprobaciones se realizaron en local; dominio, HTTPS y operación remota en el VPS siguen pendientes.

## Puntuación contextual única

La interfaz, la API web, los PDF y el contexto enviado a IA utilizan `score_interno` como única puntuación VulnSOC, sin límite superior ni denominador. CVSS mantiene su escala propia de 0–10 y EPSS su probabilidad. Los historiales antiguos con `score_mostrado` siguen siendo importables; ese campo heredado no se presenta ni interviene en la prioridad. El motor conserva un alias heredado de compatibilidad; no se utiliza para priorizar en la web.

## Metodología 2.0 · verificación del 14/09/2026

Consulta las reglas y límites en [docs-methodology.md](../docs-methodology.md). La consulta real de Log4Shell devuelve 160 puntos y prioridad crítica con CVSS, KEV y EPSS disponibles. Los ejemplos fechados de la home se han evaluado con política 2.0: Log4Shell 160, Terrapin 89. Los valores 225/119 anteriores corresponden a la metodología histórica y no son comparables directamente.

El despliegue actualiza el formato de caché de fuentes. La clave de IA incorpora fuentes, score y versión de metodología. Los historiales del navegador se conservan: la interfaz permite reanalizar explícitamente. La criticidad y la exposición se aplican solo con compatibilidad de versión, no por coincidencia de fabricante.

## Informe PDF · VulnSOC Intelligence Brief

La exportación organiza la instantánea en decisión y alcance, trazabilidad del score, evidencias técnicas y análisis asistido opcional. Conserva la descripción completa de NVD, referencias enlazadas, advertencias, fecha del análisis y activos relacionados cuando están disponibles. La fecha de exportación se indica por separado, en UTC. No consulta nuevas fuentes ni recalcula el score.

El Markdown se convierte mediante Mistune en títulos, listas, tablas y código. El HTML aportado se trata como texto; no se descargan imágenes externas. Las tablas de más de cinco columnas se presentan como registros etiquetados para conservar la legibilidad en A4. Las fuentes tipográficas se incluyen en `modules/report_fonts/`, junto a su licencia, y se copian a la imagen con los módulos.

Para actualizar esta versión, reconstruye los servicios desde la raíz del repositorio:

```bash
git pull --ff-only origin main
sudo docker compose up -d --build
```

No es necesario volver a generar el análisis de IA: exportar un resultado guardado aplica la nueva maquetación. Las pruebas `tests/test_pdf.py` comprueban paginación, contenido largo, Markdown y datos incompletos. Las comprobaciones de extracción de texto requieren `pdftotext` (Poppler) en el entorno de pruebas; no es necesario para servir la aplicación.
