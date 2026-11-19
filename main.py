# -*- coding: utf-8 -*-
"""
Sistema de Detección de Intrusiones (IDS) - Orquestador Principal
Proyecto 3: Sensor Embebido con Inteligencia Artificial (UNMSM)
"""

import os
import sys
import warnings

# Ocultar advertencias de compatibilidad entre versiones de scikit-learn
warnings.filterwarnings('ignore')

# Asegurar que Python reconozca las carpetas del proyecto
directorio_base = os.path.dirname(os.path.abspath(__file__))
if directorio_base not in sys.path:
    sys.path.insert(0, directorio_base)

from captura.captura import leer_pcap
from captura.flujos import GestorFlujos
from captura.extraer_features import extraer_features_flujo
from ml.inferencia import MotorInferencia

def main():
    print("=" * 75)
    print(" SISTEMA DE DETECCIÓN DE INTRUSIONES (IDS) - PROYECTO 3 ")
    print(" Integración: Captura de Red + Extracción de Flujos + Inferencia IA ")
    print("=" * 75)

    ruta_pcap = os.path.join(directorio_base, "data", "captura_prueba.pcap")
    ruta_models = os.path.join(directorio_base, "models") + "/"

    if not os.path.exists(ruta_pcap):
        print(f"[!] Error: No se encontró el archivo de prueba en {ruta_pcap}")
        return

    # 1. Inicializar el motor de Inteligencia Artificial (Integrante 1)
    print("\n[+] 1. Cargando modelos de Inteligencia Artificial (Random Forest, XGBoost, Autoencoder)...")
    motor = MotorInferencia(ruta_modelos=ruta_models)

    # 2. Inicializar el gestor de flujos (Integrante 2)
    print(f"\n[+] 2. Leyendo paquetes de red desde: {ruta_pcap}...")
    gestor = GestorFlujos(timeout_segundos=5.0)

    flujos = []
    total_paquetes = 0
    for pkt in leer_pcap(ruta_pcap):
        total_paquetes += 1
        terminados = gestor.procesar_paquete(pkt)
        flujos.extend(terminados)

    # Procesar los flujos restantes
    flujos.extend(gestor.vaciar_todos())

    print(f"[✓] Se procesaron {total_paquetes} paquetes de red.")
    print(f"[✓] Se identificaron {len(flujos)} conversaciones/flujos independientes.\n")

    # 3. Evaluar cada flujo con la IA y mostrar resultados en pantalla
    print("=" * 75)
    print(f"{'#':<3} | {'PUERTO':<7} | {'DURACIÓN':<11} | {'PAQUETES':<9} | {'RF (STEVEN)':<10} | {'ESTADO GENERAL'}")
    print("-" * 75)

    alertas_detectadas = 0
    for idx, flujo in enumerate(flujos, 1):
        features = extraer_features_flujo(flujo)
        prediccion = motor.evaluar_flujo(features)

        duracion_ms = f"{features['Flow Duration'] / 1000:.2f} ms"
        total_pkts = features['Total Fwd Packets'] + features['Total Backward Packets']
        estado = prediccion['alerta_general']
        rf_clasif = prediccion['RandomForest_Clasificacion']

        if estado == "SOSPECHOSO":
            alertas_detectadas += 1
            etiqueta = "🚨 SOSPECHOSO (ATAQUE)"
        else:
            etiqueta = "✅ NORMAL (BENIGNO)"

        print(f"{idx:<3} | {features['Destination Port']:<7} | {duracion_ms:<11} | {total_pkts:<9} | {rf_clasif:<10} | {etiqueta}")

    print("=" * 75)
    print(f"\n[RESUMEN FINAL]:")
    print(f" • Total de flujos analizados: {len(flujos)}")
    print(f" • Comunicaciones normales   : {len(flujos) - alertas_detectadas}")
    print(f" • Amenazas detectadas       : {alertas_detectadas}")
    print("=" * 75)

    # 4. Exportar resultados al formato que espera el Dashboard de Streamlit (Integrante 3)
    ruta_salida_dashboard = os.path.join(directorio_base, "data", "resultados_demo.csv")
    import pandas as pd
    from datetime import datetime

    registros_dash = []
    for idx, f in enumerate(flujos, 1):
        feat = extraer_features_flujo(f)
        pred = motor.evaluar_flujo(feat)
        proto = "TCP" if f.protocolo == 6 else ("UDP" if f.protocolo == 17 else str(f.protocolo))
        registros_dash.append({
            "timestamp": datetime.fromtimestamp(f.tiempo_inicio).strftime("%Y-%m-%d %H:%M:%S"),
            "flow_id": f"FLOW-{idx:03d}",
            "src_ip": f.ip_origen,
            "dst_ip": f.ip_destino,
            "protocol": proto,
            "total_packets": len(f.fwd_paquetes) + len(f.bwd_paquetes),
            "total_bytes": sum(f.fwd_paquetes) + sum(f.bwd_paquetes),
            "prediction": "sospechoso" if pred["alerta_general"] == "SOSPECHOSO" else "normal"
        })

    pd.DataFrame(registros_dash).to_csv(ruta_salida_dashboard, index=False)
    print(f"\n[✓] Resultados exportados para el Dashboard Web en: {ruta_salida_dashboard}")
    print("    Para abrir la interfaz web ejecuta: ./venv/bin/streamlit run dashboard/dashboard.py\n")

if __name__ == "__main__":
    main()
