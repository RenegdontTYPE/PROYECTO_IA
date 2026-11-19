# Especificación Técnica de Captura y Procesamiento de Flujos

**Integrante 2:** Módulo de Captura de Red y Extracción de Características  
**Proyecto:** Sistema de Detección de Intrusiones (IDS) con Sensor Embebido  
**Compatibilidad:** Modelos de Machine Learning (CIC-IDS2017)

---

## 1. Definición del Flujo de Red (5-Tupla)

Un **flujo de red** (*network flow*) representa la totalidad de la comunicación bidireccional entre dos nodos de red en un periodo de tiempo. Se identifica mediante la tupla canónica de 5 elementos:

$$\text{Clave del Flujo} = (\text{IP}_A, \text{IP}_B, \text{Puerto}_A, \text{Puerto}_B, \text{Protocolo})$$

* **Sentido Forward (Hacia adelante):** Paquetes enviados desde el iniciador de la comunicación (cliente) hacia el receptor (servidor).
* **Sentido Backward (Hacia atrás):** Paquetes de respuesta enviados desde el servidor hacia el cliente.
* **Criterios de Cierre:**
  1. Recepción de banderas TCP `FIN` (*Finalize*) o `RST` (*Reset*).
  2. Tiempo de inactividad (*timeout*) superior a 15 segundos sin observar nuevos paquetes.

---

## 2. Definición y Unidades de las 15 Características Calculadas

Las características extraídas coinciden de forma estricta con el contrato de datos del modelo de Inteligencia Artificial (`models/features.json`):

| # | Característica (*Feature*) | Unidad de Medida | Fórmula / Cálculo | Justificación en Ciberseguridad |
|---|---|---|---|---|
| 1 | `Destination Port` | Entero (0-65535) | Puerto de destino del paquete inicial | Permite detectar si el tráfico apunta a servicios comunes (80, 443) o escaneos a puertos cerrados. |
| 2 | `Flow Duration` | Microsegundos ($\mu s$) | $(T_{\text{último}} - T_{\text{inicial}}) \times 10^6$ | En ataques de escaneo o DoS los flujos suelen ser anormalmente breves o instantáneos. |
| 3 | `Total Fwd Packets` | Cantidad (Entero) | Número de paquetes enviados en sentido cliente $\to$ servidor | Escaneos de puertos envían típicamente 1 único paquete SYN hacia adelante. |
| 4 | `Total Backward Packets` | Cantidad (Entero) | Número de paquetes de respuesta servidor $\to$ cliente | Puertos cerrados responden con un solo paquete RST o ninguno. |
| 5 | `Total Length of Fwd Packets` | Bytes (Entero) | Suma de bytes de todos los paquetes Forward | Mide el volumen de datos que el cliente transmitió al servidor. |
| 6 | `Total Length of Bwd Packets` | Bytes (Entero) | Suma de bytes de todos los paquetes Backward | Tráfico web normal tiene respuestas pesadas; escaneos no tienen datos útiles. |
| 7 | `Fwd Packet Length Max` | Bytes (Entero) | $\max(\text{bytes}_{\text{fwd}})$ | Identifica si se enviaron paquetes grandes de carga útil (*payload*). |
| 8 | `Fwd Packet Length Min` | Bytes (Entero) | $\min(\text{bytes}_{\text{fwd}})$ | Paquetes de control puro (SYN) suelen medir entre 54 y 66 bytes. |
| 9 | `Fwd Packet Length Mean` | Bytes (Flotante) | $\text{Promedio}(\text{bytes}_{\text{fwd}})$ | Ayuda a distinguir peticiones normales de ráfagas sin contenido. |
| 10 | `Bwd Packet Length Max` | Bytes (Entero) | $\max(\text{bytes}_{\text{bwd}})$ | Tamaño máximo devuelto por el servidor. |
| 11 | `Bwd Packet Length Min` | Bytes (Entero) | $\min(\text{bytes}_{\text{bwd}})$ | Tamaño mínimo devuelto por el servidor. |
| 12 | `Bwd Packet Length Mean` | Bytes (Flotante) | $\text{Promedio}(\text{bytes}_{\text{bwd}})$ | Promedio de bytes devueltos. |
| 13 | `Flow Bytes/s` | Bytes / Segundo | $\frac{\text{Total Bytes}}{\text{Duración en segundos}}$ | Tasa de transferencia de datos; ráfagas de saturación disparan este valor. |
| 14 | `Flow Packets/s` | Paquetes / Segundo | $\frac{\text{Total Paquetes}}{\text{Duración en segundos}}$ | Frecuencia de transmisión; escaneos rápidos presentan valores muy elevados. |
| 15 | `Average Packet Size` | Bytes (Flotante) | $\frac{\text{Total Bytes}}{\text{Total Paquetes}}$ | Tamaño promedio ponderado de toda la conversación de red. |

---

## 3. Instrucciones de Ejecución

### Procesamiento de un archivo PCAP
```bash
# Activar entorno virtual
source venv/bin/activate

# Ejecutar test de integración automatizado
python tests/test_captura.py
```

### Uso como librería en el Dashboard o main.py
```python
from captura.captura import leer_pcap
from captura.flujos import GestorFlujos
from captura.extraer_features import extraer_features_flujo

gestor = GestorFlujos(timeout_segundos=15.0)

for pkt in leer_pcap("data/captura_prueba.pcap"):
    flujos_terminados = gestor.procesar_paquete(pkt)
    for flujo in flujos_terminados:
        features = extraer_features_flujo(flujo)
        # Enviar directamente a MotorInferencia
```
