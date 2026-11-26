# Guion de demo (3 minutos)

## 0. Levantar el servicio

```powershell
.\run.bat
```

Mostrar en la terminal: `Uvicorn running on http://127.0.0.1:8000`.

## 1. Probar que está sirviendo (30 s)

```powershell
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/metrics
curl http://127.0.0.1:8000/api/config
```

Abrir <http://127.0.0.1:8000/docs> y ejecutar `GET /health` desde Swagger.
Señalar el indicador verde de la UI: consulta `/health` cada 5 s.

## 2. Escenario legítimo (40 s)

Clic en **Deploy legítimo**.

Mostrar:
- CPU ~22% → ~78%, red saliente ~18 KB/s → ~92 KB/s.
- Clasificación: **Crecimiento legítimo probable**.
- Evidencia: evento `deploy v2.4`, sin IPs nuevas, sin persistencia nueva.
- Frase: "El mismo pico que antes parecía sospechoso, aquí tiene una causa declarada".

## 3. Escenario sospechoso (40 s)

Clic en **Pico sospechoso**.

Mostrar:
- Clasificación: **Indicios de uso indebido**, severidad alta.
- Evidencia: proceso nuevo, dos IPs públicas nuevas, entrada `sysupdate` y tarea programada nueva.
- Advertencia visible: "No confirma minería ilícita; requiere verificación".
- Panel **Procesos y conexiones observadas**: `python (script)` con PID, padre `cmd.exe`, cmdline codificada y las dos IPs atribuidas.
- Mensaje: "Demo sintética: no se guardó en la base de datos".

## 4. Escaneo local real + actividad (60 s)

1. Elegir perfil (por defecto **Estación de trabajo**; probar **Servidor** para ver que baja el umbral).
2. Registrar `deploy` con detalle `release v2.4 de prueba`, duración `5` min y procesos esperados `python, node`.
3. Elegir el tiempo: preset `Rápido 2+2` para la demo o `Extendido 15+15` para un caso real.
4. Clic en **Escanear mi PC** (2×segundos elegidos).
5. Mostrar `chart-source = escaneo local`, serie real y `warnings` si faltan permisos de red.
6. Mostrar el panel de procesos: PID real, padre, ruta/cmdline truncada, etiqueta **declarado como esperado** y a qué PID pertenece cada IP pública.
7. Repetir sin registrar actividad para comparar la explicación.

> En una PC en reposo lo normal es obtener `Comportamiento normal` o `Sin conclusión`.
> Eso es correcto: el sistema no inventa un incidente.

## 5. Línea base y monitor (30 s)

```powershell
curl http://127.0.0.1:8000/api/baseline
curl http://127.0.0.1:8000/api/monitor/status
```

Mostrar el panel **Línea base histórica**: con menos de 20 muestras dice `historial insuficiente` y
solo compara las dos fases del escaneo. Iniciar el monitor con `10 s` durante `1 min` y explicar que
acumula muestras reales en segundo plano, sin generar veredictos. Volver a escanear después de
unas muestras para ver cómo aparece el p95 en **Contexto de la decisión**.

## 6. Cierre (20 s)

```powershell
curl http://127.0.0.1:8000/api/history?limit=5
```

Señalar que aparecen solo escaneos `source=local`: los botones de demo no ensucian el historial.

Mensaje final:
"Detecta la desviación, explica el contexto y propone verificaciones. No acusa minería por un pico de CPU."

## Preguntas probables

- **¿Por qué no solo LLM?** Porque alucina y no audita; aquí el LLM es opcional y solo redacta.
- **¿Puede dar falsos positivos?** Sí; por eso existe `inconclusive` y la lista de verificaciones.
- **¿Cómo sabe qué proceso genera el tráfico?** Lee las conexiones `ESTABLISHED` con `psutil` y las asocia al PID dueño; si no hay permisos, lo avisa en `warnings`.
- **¿Toca algo del equipo?** No: el escáner es de solo lectura. Remediación queda fuera del alcance.
- **¿El LLM decide la etiqueta?** No; es opcional y solo reescribe el resumen y las verificaciones.
- **¿Un proceso declarado como esperado se vuelve "seguro"?** No; solo deja de ser desconocido.Las conexiones públicas o banderas fuertes siguen requiriendo verificación.
- **¿El monitor guarda comandos?** No; guarda métricas agregadas y nombres de procesos/IPs para el p95.
