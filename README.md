# Centinela de Consumo

Detector de consumo anómalo con explicación contextual. No se limita a decir "subió la CPU":
compara una línea base con la ventana observada, correlaciona señales de actividad y
clasifica entre **crecimiento legítimo**, **indicios de uso indebido** o **sin conclusión**.

> Un pico de CPU **nunca** se presenta como minería confirmada. El sistema lo dice explícitamente.

## Ejecutar

### Opción A — Python (recomendado para desarrollo)

```powershell
pip install -r backend\requirements.txt
.\run.bat
```

Duración por defecto del escaneo (configurable):

```powershell
$env:DETECTOR_BASELINE_SECONDS = "15"
$env:DETECTOR_WINDOW_SECONDS = "15"
.\run.bat
```

También se puede cambiar en la UI con los campos **Línea base / Ventana observada** o los presets `Rápido 2+2`, `Estándar 4+4` y `Extendido 15+15` (rango permitido: 2-300 s por fase).

Abrir: <http://127.0.0.1:8000/app/index.html>

### Opción B — Docker

```powershell
docker compose up --build
```

Abrir: <http://localhost:8000/app/index.html>

## Qué incluye

| Parte | Tecnología | Uso |
|---|---|---|
| API | FastAPI + Pydantic | `/health`, `/metrics`, `/api/config`, `/api/analyze`, `/api/history`, `/api/events`, `/api/baseline`, `/api/monitor/*`, `/docs` |
| Front | HTML/CSS/JS estático servido por FastAPI | Sin build, sin npm; gráfica SVG y panel de explicación |
| Escáner local | `psutil` + `winreg` + `schtasks` | CPU, memoria, red, discos, **PID, exe, línea de comandos, padre, conexiones por PID**, IPs públicas y persistencia con nombres (solo lectura) |
| Modelo | Reglas transparentes + IsolationForest (scikit-learn) | Score 0-1 y clasificación explicable |
| Persistencia | SQLite (`data/analyses.db`) | Historial **solo de escaneos reales** y muestras para línea base; los escenarios nunca se guardan |
| Explicación | Plantillas deterministas + LLM opcional (Ollama) | Redacción en lenguaje natural; el LLM no decide la etiqueta |

## Modelo (por qué es híbrido)

1. **Línea base vs ventana:** se comparan dos mitades de la serie temporal (o dos fases del escaneo local).
2. **Score:** combinación ponderada de CPU, red saliente, proceso nuevo dominante, IP externa nueva,
   persistencia y memoria. IsolationForest modula el número; las reglas explican la decisión.
3. **Clasificación:**
   - `suspicious`: CPU alta + proceso nuevo + (IP externa, persistencia o señales de ofuscación/temporal/shell), sin actividad declarada.
   - `legitimate_growth`: CPU alta coincide con deploy/backup/job o con crecimiento simultáneo de carga y workers, sin señales de abuso.
   - `inconclusive`: desviación sin correlaciones suficientes para atribuir causa.
   - `normal`: dentro de la línea base.
4. **Salida:** evidencia a favor y en contra, verificaciones sugeridas y una advertencia explícita
   de que la correlación no prueba causalidad.

## Escanear mi PC

El botón **Escanear mi PC** ejecuta un muestreo local (por defecto 4 s de línea base + 4 s de ventana):

- Lee contadores de CPU, memoria, red y disco con `psutil`.
- Agrega los procesos con mayor CPU y, para los nuevos, muestra **PID, ruta del ejecutable,
  línea de comandos, proceso padre y banderas** (temporal, ofuscación, shell, conexión saliente).
- Lista destinos **públicos** de conexiones `ESTABLISHED` y los atribuye al **PID dueño** de la conexión.
- En Windows lee los **nombres y valores** de las entradas `HKCU\...\Run` y los **nombres** de las
  tareas programadas, para identificar nuevas entradas de persistencia (no solo un contador).
- Compara contra `data/events.jsonl`, donde puedes registrar un deploy/backup/job desde el front.

**Límites y privacidad:** es solo lectura; no termina procesos, no modifica registros ni envía datos
a ningún servicio (salvo que actives un LLM local). La línea de comandos y los valores de `Run`
pueden contener rutas de tu usuario: se muestran en pantalla y se guardan en el historial local,
pero no salen del equipo. Si no hay permisos para leer conexiones, la API lo avisa en `warnings`
y no evalúa IPs externas. El escaneo observable es de corta duración: para un caso real se recomienda
ampliar la ventana con el preset **Extendido 15+15** y conservar el historial.

### Perfil y expectativas declaradas

El selector **Perfil del equipo** cambia los umbrales de explicación (no los datos medidos):

| Perfil | CPU | Red saliente | Pensado para |
|---|---:|---:|---|
| Estación de trabajo | +40% | +100% | Equipo de usuario |
| Servidor | +25% | +75% | Cambios sostenidos que merecen contexto |
| Desarrollo | +60% | +200% | Compilaciones, contenedores, workers declarados |

Al registrar una actividad puedes indicar **duración** y **procesos esperados**. La ventana declarada
debe solaparse con el escaneo para contar como explicación; un proceso declarado deja de ser
"nuevo/desconocido", pero una conexión pública sin explicar sigue pidiendo verificación.
Los eventos siguen siendo **notas del analista**: no crean deployments ni tareas.

### Línea base histórica y monitor

Cada escaneo local guarda muestras reales (CPU, memoria, red, número de procesos, nombres de los
procesos con más CPU e IPs públicas; **no** cmdline ni valores de `Run`). Con al menos 20 muestras
en 14 días, el análisis compara la ventana actual contra el **p95 histórico** y lo muestra en
**Contexto de la decisión** y en **Línea base histórica**. Si no hay suficientes muestras, lo dice
explícitamente y solo compara las dos fases del escaneo.

El **Modo monitor** acumula muestras en segundo plano cada N segundos durante una duración acotada,
sin producir veredictos ni guardar análisis. Se controla desde la UI o con
`POST /api/monitor/start`, `/api/monitor/status` y `/api/monitor/stop`.
Los escenarios de demo **no** consultan ni contaminan esta línea base.

### Escenarios de demo (no se guardan)

Los cuatro botones de escenario son datos **sintéticos deterministas** para la demostración.
Sus respuestas incluyen `"persisted": false` y **no** se escriben en `data/analyses.db`.
Al iniciar, la API elimina los registros `source='scenario'` de versiones anteriores.
`/api/history` solo muestra escaneos `source='local'`.

### Verificación configurable

- UI: campos **Línea base (s)** y **Ventana observada (s)** + presets `2+2`, `4+4`, `15+15`.
- API: `POST /api/analyze` con `{"source":"local","baseline_seconds":15,"window_seconds":15,"profile":"server"}`.
- Variables de entorno: `DETECTOR_BASELINE_SECONDS`, `DETECTOR_WINDOW_SECONDS`,
  `DETECTOR_MONITOR_INTERVAL`, `DETECTOR_MONITOR_MINUTES`.
- Eventos: `POST /api/events` con `{"type":"deploy","detail":"v2.4","duration_minutes":10,
  "expected_processes":["node","docker"]}` (en PowerShell guarda el JSON en una variable antes de pasarlo).
- Límites: 2-300 s por fase; `GET /api/config` devuelve perfiles y valores vigentes.

## Demostrar que el servicio está sirviendo

```powershell
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/metrics
curl http://127.0.0.1:8000/api/config
curl http://127.0.0.1:8000/api/baseline
curl http://127.0.0.1:8000/api/monitor/status
curl http://127.0.0.1:8000/api/scenarios
$demo = '{"source":"scenario","scenario":"suspicious_spike","profile":"server"}'
curl.exe -X POST http://127.0.0.1:8000/api/analyze -H "Content-Type: application/json" -d $demo
$local = '{"source":"local","baseline_seconds":15,"window_seconds":15,"profile":"workstation"}'
curl.exe -X POST http://127.0.0.1:8000/api/analyze -H "Content-Type: application/json" -d $local
$monitor = '{"interval_seconds":10,"duration_minutes":1}'
curl.exe -X POST http://127.0.0.1:8000/api/monitor/start -H "Content-Type: application/json" -d $monitor
```

- El indicador verde de la cabecera consulta `/health` cada 5 segundos.
- `/docs` expone la API interactiva generada por FastAPI.
- `/metrics` muestra contadores de peticiones, análisis por etiqueta y último score.
- Cada respuesta incluye `id`, `model`, `warnings` y `persisted`; solo las reales aparecen en `/api/history`.
- El panel **Procesos y conexiones observadas** muestra PID/padre/cmdline y la atribución de cada IP nueva.

Guion paso a paso: [`docs/demo-script.md`](docs/demo-script.md).

## LLM opcional

`run.bat` activa por defecto el LLM local con Ollama (`llama3.2:3b`, timeout 30 s). Para instalarlo:

```powershell
winget install --id Ollama.Ollama -e --accept-source-agreements --accept-package-agreements
ollama pull llama3.2:3b
.\run.bat
```

Comprueba `/health`: debe aparecer `"llm_configured": true`. En cada respuesta verás `llm_used: true`
cuando el modelo respondió. Para volver al modo determinista:

```powershell
$env:DETECTOR_LLM_URL = "off"
.\run.bat
```

El LLM solo añade una frase de lectura al `summary` y reescribe `verifications`. Las cifras y el
caveat del texto determinista se conservan siempre. Nunca cambia `label`, `score`, evidencias ni
advertencias; si falla o demora, se usa la explicación determinista y se añade un aviso.

## Tests

```powershell
python -m pytest backend/tests -q
```

## Estructura

```text
backend/app/main.py        endpoints y enrutamiento de peticiones
backend/app/collector.py   escáner local (psutil, solo lectura)
backend/app/features.py    línea base, deltas y señales
backend/app/detector.py    score híbrido (reglas + IsolationForest)
backend/app/rules.py       clasificación y verificaciones
backend/app/explain.py     texto explicativo y LLM opcional
backend/app/scenarios.py   escenarios deterministas de demo
backend/app/events.py      notas del analista con ventana y procesos esperados
backend/app/monitor.py     muestreo en segundo plano para la línea base
backend/app/store.py       historial SQLite y muestras para p95
frontend/                  UI estática (chart SVG + panel)
data/                      SQLite y eventos (se crea automáticamente)
```
