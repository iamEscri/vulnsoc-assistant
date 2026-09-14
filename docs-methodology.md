# Metodología VulnSOC 2.0

VulnSOC es una ayuda a la priorización. Sus puntos son una **política heurística explícita**, no una probabilidad de compromiso ni un modelo de riesgo calibrado. Los pesos y umbrales no están prescritos por NVD, FIRST o CISA. Las pruebas verifican consistencia y regresiones; no demuestran precisión predictiva en producción.

## Decisión y puntuación

La prioridad es el resultado principal. Los puntos permiten explicar y ordenar resultados **de la misma versión de metodología**. No se aplica un tope ni un denominador.

| Factor | Política 2.0 |
|---|---|
| Severidad | CVSS base × 10, redondeado a entero |
| Explotación documentada | KEV incluido: +60; prioridad al menos alta (90 puntos). Si hace falta, un factor explícito completa ese mínimo. |
| Probabilidad predictiva | Solo si no está incluido en KEV: EPSS ≥1% +10; ≥10% +20; ≥70% +30. Los tramos no se acumulan. |
| Activo compatible | +5 por compatibilidad de producto y versión, +15 criticidad alta / +5 media / +0 baja; +15 exposición declarada a Internet. |
| Vector, CWE, recencia | Evidencia descriptiva, sin bonificaciones adicionales. CVSS ya incorpora la explotabilidad técnica; CWE no prueba ejecución remota. |
| Inventario sin coincidencia | 0. No se resta prioridad ni se declara el entorno seguro. |

Se toma la contribución de **un solo activo**, el de mayor contribución conjunta. No se suman activos ni se mezcla la criticidad de uno con la exposición de otro. No se deduce exposición a partir de una IP o del vector CVSS. La exposición es declarada por el usuario, no verificada mediante escaneo.

Umbrales de política: baja <55; media 55–89; alta 90–129; crítica ≥130. Sin CVSS utilizable y sin KEV confirmado: **sin determinar**, aunque se conserven puntos parciales para explicar las evidencias. KEV sin CVSS activa el mínimo de alta y se marca provisional. Baja nunca significa segura.

Los pesos actuales permiten hasta 195 puntos. Este máximo es consecuencia de la política actual, no un límite artificial ni una escala porcentual. Si cambia la política, cambia la versión.

### Justificación y límites

- CVSS se incorpora una vez; no se vuelven a sumar sus atributos de explotabilidad ni una clasificación CWE.
- KEV tiene precedencia sobre EPSS; la evidencia de explotación no se cancela por una predicción baja. Ambos pueden mostrarse, pero no reciben bonificaciones simultáneas.
- Los tramos EPSS son una decisión de producto: permiten distinguir probabilidades bajas pero no nulas. No se anuncian como umbrales óptimos. EPSS también contiene características relacionadas con CVSS: separar las aportaciones **no demuestra independencia estadística**.
- No se asignan plazos de parche universales. La acción sugerida requiere comprobar aplicabilidad y contexto operativo. La fecha de CISA pertenece al ámbito de su directiva.

## Guía dentro de la aplicación

La sección **Metodología** y el desplegable **Entender el scoring · reglas y ejemplos** del desglose explican la política sin requerir un análisis previo. Sus escenarios son didácticos, no consultas actuales, y no se incorporan al historial:

| Escenario | Suma | Prioridad |
|---|---|---|
| CVSS 7,2, sin KEV, EPSS 0,50 % | 72 + 0 = 72 | Media |
| CVSS 9,8, sin KEV, EPSS 80 % | 98 + 30 = 128 | Alta |
| CVSS 10, KEV confirmado, EPSS 99,999 % | 100 + 60 + 0 = 160 | Crítica |
| CVSS 9,8, sin KEV, EPSS 0,50 %, activo compatible de criticidad alta expuesto a Internet | 98 + 5 + 15 + 15 = 133 | Crítica |
| CVSS ausente, KEV confirmado | 60 + 30 de mínimo operativo = 90 | Alta provisional |

Los valores de los ejemplos publicados se verifican contra el motor en las pruebas. La interfaz distingue EPSS sin datos, EPSS inferior al primer umbral y EPSS informativo por precedencia de KEV. La aplicabilidad al inventario se presenta por separado; se conserva la advertencia y el estado provisional del informe cuando falta contexto verificable.

## Interpretar datos incompletos

`0`, `false`, `null` y error tienen significados distintos. CVSS ausente no es cero. EPSS sin registros o con error se devuelve como `null`, nunca como 0%. KEV sin verificar no equivale a no listado. Las advertencias acompañan al resultado en interfaz, PDF y contexto de IA.

La prioridad es provisional cuando faltan fuentes, hay fechas inválidas/futuras o el inventario no puede verificarse. Sin inventario se presenta prioridad general, no riesgo de activos concretos. Una puntuación conocida se conserva como evidencia parcial, sin presentarla como evaluación completa.

Búsqueda y análisis comparten selección CVSS: 4.0 → 3.1 → 3.0 → 2.0; dentro de una versión se prioriza una evaluación Primary, y NVD entre candidatos del mismo tipo. Se conserva fuente y vector. Comparar versiones CVSS diferentes también requiere cautela.

## Inventario: alcance de la comprobación

Se compara identidad completa del producto, o su nombre específico en los CPE publicados; nunca cualquier palabra del fabricante. Apache Tomcat no coincide con Apache Log4j por compartir «Apache».

Se admite `Apache Log4j 2.14.1` o un CPE 2.3. Las versiones numéricas simples se comparan con inclusividad/exclusividad de los rangos NVD. Versiones ambiguas, atributos adicionales de CPE y configuraciones con AND/negación quedan pendientes: no implementamos un evaluador completo de toda la lógica CPE.

Estados:

- **Posible:** identidad relacionada, versión o condiciones sin verificar. Sin puntos de contexto.
- **Versión compatible:** versión dentro de un criterio sencillo publicado. Permite ponderar contexto; **no confirma que todas las condiciones de explotación se cumplan ni que el activo esté comprometido**.
- **Fuera de rango:** fuera de los criterios comparables revisados. No se etiqueta como seguro y no se resta prioridad.
- **Sin coincidencias:** inventario o evidencias pueden estar incompletos.

## Reproducibilidad e informes antiguos

Cada resultado 2.0 incluye `metodologia_version`, factores, calidad de datos, advertencias, contexto y acción sugerida. Las fuentes incluyen fechas de consulta cuando están disponibles. Los informes antiguos no se recalculan al importar: conservan sus datos y se identifican como históricos. «Actualizar análisis» consulta fuentes, aplica política actual e inventario actual y reemplaza la entrada de ese CVE. Exportar antes permite conservar ambas instantáneas.

La caché de fuentes usa una nueva clave de formato y la de IA incorpora resultado y metodología. Los ejemplos de la home utilizan instantáneas fechadas, recalculadas por el motor, sin inventario; no se insertan en el historial.

## Validación antes de afirmar eficacia

La suite cubre RCE sin KEV, precedencia KEV, umbrales EPSS, ausencia frente a cero, identidad de producto, límites de versión, AND/negación, criticidad/exposición y CVSS 4.0. No sustituye un estudio empírico. Una futura calibración requiere un conjunto fechado de decisiones expertas/activos y una evaluación temporal independiente, sin utilizar KEV futuro para predecir el pasado. Publicar como herramienta explicable con limitaciones, no como detector validado de compromiso.

## Fuentes de referencia

- [NVD: API de vulnerabilidades y configuraciones CPE](https://nvd.nist.gov/developers/vulnerabilities)
- [FIRST: uso de EPSS y precedencia de explotación conocida](https://www.first.org/epss/using-epss)
- [FIRST: preguntas frecuentes sobre EPSS](https://www.first.org/epss/faq)

Estas fuentes explican los datos. No avalan los pesos propios de VulnSOC.
