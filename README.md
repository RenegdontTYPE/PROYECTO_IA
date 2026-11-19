# 🛡️ Sistema de Detección de Intrusiones en Red (NIDS) con Sensor Embebido e Inteligencia Artificial

> **Proyecto:** Sistema de detección de anomalías y ataques en tráfico de red con un sensor embebido de bajo costo  
> **Institución:** Universidad Nacional Mayor de San Marcos (UNMSM)  
> **Facultad:** Facultad de Ingeniería Electrónica y Eléctrica (FIEE)  
> **Escuela Profesional:** Ingeniería de Telecomunicaciones  
> **Curso:** Inteligencia Artificial — Semestre 2026-II  

---

## 📌 1. Descripción del Proyecto

Este proyecto consiste en el diseño, implementación y evaluación de un **NIDS** (*Network Intrusion Detection System* / Sistema de Detección de Intrusiones en Red) pasivo y de bajo costo. 

El sistema monitorea el tráfico de una red local conectándose a un switch administrable mediante **Port Mirroring** (espejado de puertos). Utiliza una **Raspberry Pi** como sensor embebido, la cual agrupa los paquetes de red en **flujos bidireccionales**, calcula **15 características estadísticas clave** basadas en el estándar de referencia académico **CIC-IDS2017**, y clasifica las comunicaciones en tiempo real empleando una arquitectura híbrida de Machine Learning y Deep Learning:
1. **Random Forest (100 árboles):** Clasificación supervisada veloz para ataques conocidos (*PortScan*).
2. **XGBoost:** Máxima precisión probabilística y baja tasa de falsos positivos.
3. **Autoencoder en PyTorch:** Red neuronal profunda de compresión y descompresión para detección no supervisada de anomalías desconocidas (*Zero-Day*).

Las alertas, estadísticas de flujo y métricas se presentan en tiempo real en un **Dashboard web interactivo desarrollado en Streamlit**.

---

## 🏗️ 2. Arquitectura General del Sistema

```text
[ Red de Prueba: Laptops Víctima y Atacante ]
                      │
                      ▼
        [ Switch Administrable (Port Mirroring) ]
                      │ (Copia idéntica del tráfico)
                      ▼
    ┌─────────────────────────────────────────────────────────────┐
    │          SENSOR EMBEBIDO (Raspberry Pi / Linux)             │
    │                                                             │
    │  1. CAPTURA: Scapy (lectura en streaming con generadores)   │
    │  2. GESTIÓN: Agrupación en 5-Tuplas (Forward / Backward)   │
    │  3. EXTRACCIÓN: Cálculo de 15 variables en microsegundos    │
    │  4. INFERENCIA: Random Forest + XGBoost + Autoencoder (MSE) │
    │  5. ALMACENAMIENTO: Registro en memoria / CSV               │
    └─────────────────────────────────────────────────────────────┘
                      │
                      ▼
[ Dashboard Web en Streamlit (http://localhost:8501) ]
```

---

## 📁 3. Estructura del Repositorio

```text
PROYECTO_IA/
├── captura/                 # MÓDULO INTEGRANTE 2: Captura y Procesamiento de Red
│   ├── captura.py           # Lectura de paquetes (PCAP y captura en vivo con Scapy)
│   ├── flujos.py            # Agrupador de conversaciones (5-tuplas y control de timeouts)
│   ├── extraer_features.py  # Cálculo matemático de las 15 variables del modelo
│   └── requisitos_captura.md# Especificación formal de variables, fórmulas y unidades
├── dashboard/               # MÓDULO INTEGRANTE 3: Interfaz Gráfica y Monitoreo
│   └── dashboard.py         # Aplicación web en Streamlit (gráficas, KPIs y alertas)
├── ml/                      # MÓDULO INTEGRANTE 1: Inteligencia Artificial
│   ├── entrenar.py          # Script de entrenamiento en Google Colab con CIC-IDS2017
│   ├── inferencia.py        # Clase MotorInferencia para clasificar flujos en vivo
│   ├── metricas.json        # Métricas de precisión, recall y matriz de confusión
│   └── matriz_confusion.png # Visualización del rendimiento de los clasificadores
├── models/                  # Pesos y configuraciones de los modelos entrenados
│   ├── autoencoder.pth      # Pesos de la red neuronal en PyTorch
│   ├── features.json        # Contrato de las 15 características esperadas
│   ├── label_encoder.joblib # Codificador de clases (BENIGN = 0, PortScan = 1)
│   ├── rf_model.joblib      # Modelo entrenado de Random Forest
│   ├── scaler.joblib        # Normalizador de datos (StandardScaler)
│   ├── umbral.json          # Umbral de error de reconstrucción MSE (1.2344)
│   └── xgb_model.json       # Modelo entrenado de XGBoost
├── data/                    # Datos de prueba y resultados
│   ├── captura_prueba.pcap  # Captura de paquetes reales (tráfico normal + escaneo)
│   ├── flujos_prueba.csv    # Flujos calculados por el módulo de captura
│   └── resultados_demo.csv  # Predicciones formateadas para el Dashboard
├── tests/                   # Pruebas automatizadas de integración
│   └── test_captura.py      # Test que certifica la compatibilidad Captura <-> IA
├── main.py                  # Orquestador general del sistema NIDS
├── requirements.txt         # Dependencias oficiales de Python
└── README.md                # Documentación del proyecto
```

---

## ⚙️ 4. Instalación y Puesta en Marcha

### En Linux (Ubuntu / Debian / Raspberry Pi OS):

```bash
# 1. Clonar el repositorio
git clone https://github.com/RenegdontTYPE/PROYECTO_IA.git
cd PROYECTO_IA

# 2. Crear y activar entorno virtual
python3 -m venv venv
source venv/bin/activate

# 3. Instalar librerías requeridas
pip install -r requirements.txt
```

### En Windows:

```cmd
:: 1. Clonar el repositorio
git clone https://github.com/RenegdontTYPE/PROYECTO_IA.git
cd PROYECTO_IA

:: 2. Crear y activar entorno virtual
python -m venv venv
venv\Scripts\activate

:: 3. Instalar librerías requeridas
pip install -r requirements.txt
```
*(Nota para Windows: Para capturas en vivo de tarjeta de red se requiere instalar [Npcap](https://npcap.com/)).*

---

## 🚀 5. Modos de Ejecución

### Opción A: Ejecutar el Sistema Completo de Extremo a Extremo (Consola)
Procesa la captura de tráfico, extrae las 15 variables, evalúa con la Inteligencia Artificial y exporta los datos:
```bash
python main.py
```

### Opción B: Ejecutar la Interfaz Web (Dashboard)
Abre el panel interactivo en tu navegador web:
```bash
streamlit run dashboard/dashboard.py
```
*Se abrirá automáticamente en `http://localhost:8501` mostrando contadores, gráficas temporales y tabla de flujos clasificados.*

### Opción C: Ejecutar Pruebas Automatizadas de Integración
Valida que el contrato de datos entre captura y Machine Learning se cumpla sin errores:
```bash
python tests/test_captura.py
```

---

## 📊 6. Las 15 Características Calculadas

| # | Característica | Unidad | Descripción |
|---|---|---|---|
| 1 | `Destination Port` | Entero | Puerto de destino del flujo |
| 2 | `Flow Duration` | $\mu s$ | Duración en microsegundos |
| 3 | `Total Fwd Packets` | Entero | Paquetes en sentido Forward (Cliente $\to$ Servidor) |
| 4 | `Total Backward Packets` | Entero | Paquetes en sentido Backward (Servidor $\to$ Cliente) |
| 5 | `Total Length of Fwd Packets` | Bytes | Volumen transmitido por el cliente |
| 6 | `Total Length of Bwd Packets` | Bytes | Volumen transmitido por el servidor |
| 7 | `Fwd Packet Length Max` | Bytes | Tamaño máximo de paquete Forward |
| 8 | `Fwd Packet Length Min` | Bytes | Tamaño mínimo de paquete Forward |
| 9 | `Fwd Packet Length Mean` | Bytes | Tamaño promedio de paquete Forward |
| 10 | `Bwd Packet Length Max` | Bytes | Tamaño máximo de paquete Backward |
| 11 | `Bwd Packet Length Min` | Bytes | Tamaño mínimo de paquete Backward |
| 12 | `Bwd Packet Length Mean` | Bytes | Tamaño promedio de paquete Backward |
| 13 | `Flow Bytes/s` | Bytes/s | Tasa de transferencia en bytes por segundo |
| 14 | `Flow Packets/s` | Pkts/s | Frecuencia de transmisión en paquetes por segundo |
| 15 | `Average Packet Size` | Bytes | Tamaño medio general de paquete en la conversación |

---

## 👥 7. Integrantes y Asignación de Roles

* **Integrante 1 (Steven):** Modelos de Machine Learning y Deep Learning (Random Forest, XGBoost, Autoencoder en PyTorch).
* **Integrante 2:** Captura de paquetes en streaming con Scapy, gestor de flujos bidireccionales y extracción de características numéricas.
* **Integrante 3 (Alex):** Dashboard interactivo de visualización y monitoreo de alertas en Streamlit.
