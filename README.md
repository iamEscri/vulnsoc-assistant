# VulnSOC Assistant

Herramienta personal y profesional de **Vulnerability Intelligence**, creada por [iamEscri](https://github.com/iamEscri). Nació como TFM de ciberseguridad y evolucionó hacia una interfaz React con una API Python.

Combina NVD, CISA KEV y FIRST EPSS con una política de priorización explicable. El resultado incluye prioridad, puntos, factores y limitaciones de los datos. La IA complementa las evidencias; no determina el score.

## Funcionalidades

- Análisis individual y por lotes de CVEs.
- Búsqueda por descripción o producto y versión CPE.
- Puntuación contextual única, sin tope artificial, con desglose interactivo.
- Inventario local con tecnologías, criticidad y exposición declarada.
- Correlación conservadora de producto y versión; no es un escáner ni confirma compromiso.
- Historial local, importación/exportación JSON y actualización de informes históricos.
- Análisis de IA, borradores Sigma y exportación PDF.
- Ejemplos fechados de Log4Shell y Terrapin, separados del historial.
- Interfaz adaptable con navegación superior y movimiento reducido.

## Metodología 2.0

[Reglas completas, justificación y límites](docs-methodology.md).

CVSS se incorpora una sola vez. KEV tiene precedencia sobre EPSS. La criticidad y la exposición solo ponderan candidatos con versión compatible. No encontrar un producto no resta puntos. Los datos desconocidos no se convierten en cero ni en baja prioridad.

| Prioridad | Puntos |
|---|---|
| Baja | <55 |
| Media | 55–89 |
| Alta | 90–129 |
| Crítica | ≥130 |
| Sin determinar | Sin CVSS utilizable ni KEV confirmado |

Son umbrales propios de una **política heurística**, no un estándar certificado ni una probabilidad calibrada. Las fuentes incompletas producen advertencias y resultados provisionales. Cada informe conserva su versión de metodología; no compares directamente puntos de versiones diferentes.

## Ejecutar en local

Requiere Python 3.12 y Node compatible con las dependencias del frontend.

```bash
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.lock
npm ci --prefix frontend
python3 scripts/dev.py
```

Abre http://127.0.0.1:5173. Mantén la terminal abierta; Ctrl+C detiene web y API. La API escucha solo en localhost:8010 y su documentación está en `/api/docs`.

Configura las claves en `.env` siguiendo `.env.example`. Las consultas oficiales y el PDF no requieren IA. Groq requiere una clave para generar análisis o Sigma cuando no hay una regla recuperable. Las claves permanecen en el servidor y nunca deben subirse al repositorio.

## Validación

```bash
npm run build --prefix frontend
npm test --prefix frontend
.venv/bin/python -m unittest discover -s tests -v
npx --prefix frontend playwright test --config frontend/playwright.config.ts workspace.spec.ts
```

Playwright requiere Chromium instalado y la web arrancada. Las pruebas de interfaz habituales simulan las respuestas de servicios. La prueba `live.spec.ts` es voluntaria: usa fuentes y proveedor reales y consume cuota; consulta la [guía de despliegue](deploy/README.md).

Las pruebas verifican regresiones y consistencia de política, no eficacia predictiva ni detecciones Sigma en producción.

## Publicación y datos

[Guía de VPS, Docker Compose, HTTPS y operación](deploy/README.md).

El historial y el inventario permanecen en IndexedDB del navegador. El inventario se envía al backend para contextualizar un análisis. No existen cuentas ni sincronización entre dispositivos. Exporta tus datos antes de cambiar de dominio o borrar el almacenamiento del navegador.

La IA puede cometer errores. Los borradores Sigma requieren revisión y pruebas técnicas. Las referencias del proveedor y la configuración real del activo deben verificarse antes de decidir una remediación.

El código Streamlit original (`app.py`) se conserva como referencia del TFM. La aplicación web mantenida se inicia con React y FastAPI según estas instrucciones.

## Fuentes

[NVD](https://nvd.nist.gov/) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [FIRST EPSS](https://www.first.org/epss/)

Proyecto independiente: estas organizaciones no avalan los pesos propios de VulnSOC.
