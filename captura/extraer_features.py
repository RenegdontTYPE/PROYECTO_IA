# -*- coding: utf-8 -*-
"""
Módulo de Extracción de Características (Integrante 2)
Calcula las 15 características numéricas exactas que espera el modelo de Machine Learning.
"""

from typing import Dict, Any, List
import pandas as pd
from captura.flujos import FlujoRed

# Lista de las 15 características acordadas en models/features.json
CARACTERISTICAS_ESPERADAS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Average Packet Size"
]

def extraer_features_flujo(flujo: FlujoRed) -> Dict[str, Any]:
    """
    Recibe un objeto FlujoRed y devuelve un diccionario con las 15 variables exactas
    listas para ser enviadas al Motor de Inferencia de Machine Learning.
    """
    fwd = flujo.fwd_paquetes
    bwd = flujo.bwd_paquetes

    total_fwd_pkts = len(fwd)
    total_bwd_pkts = len(bwd)
    total_pkts = total_fwd_pkts + total_bwd_pkts

    total_fwd_len = sum(fwd)
    total_bwd_len = sum(bwd)
    total_bytes = total_fwd_len + total_bwd_len

    # Duración en segundos y en microsegundos (CIC-IDS2017 usa microsegundos)
    duracion_segundos = max(flujo.tiempo_ultimo - flujo.tiempo_inicio, 0.0)
    duracion_microsegundos = int(duracion_segundos * 1_000_000)

    # Estadísticas de paquetes hacia adelante (Forward)
    fwd_max = max(fwd) if fwd else 0
    fwd_min = min(fwd) if fwd else 0
    fwd_mean = (total_fwd_len / total_fwd_pkts) if total_fwd_pkts > 0 else 0.0

    # Estadísticas de paquetes hacia atrás (Backward)
    bwd_max = max(bwd) if bwd else 0
    bwd_min = min(bwd) if bwd else 0
    bwd_mean = (total_bwd_len / total_bwd_pkts) if total_bwd_pkts > 0 else 0.0

    # Tasas por segundo (evitando división por cero)
    if duracion_segundos > 0:
        flow_bytes_s = total_bytes / duracion_segundos
        flow_pkts_s = total_pkts / duracion_segundos
    else:
        # En flujos instantáneos (ej. 1 paquete SYN), se asigna 0.0
        flow_bytes_s = 0.0
        flow_pkts_s = 0.0

    # Tamaño promedio de paquete en todo el flujo
    avg_packet_size = (total_bytes / total_pkts) if total_pkts > 0 else 0.0

    return {
        "Destination Port": int(flujo.puerto_destino),
        "Flow Duration": duracion_microsegundos,
        "Total Fwd Packets": total_fwd_pkts,
        "Total Backward Packets": total_bwd_pkts,
        "Total Length of Fwd Packets": total_fwd_len,
        "Total Length of Bwd Packets": total_bwd_len,
        "Fwd Packet Length Max": fwd_max,
        "Fwd Packet Length Min": fwd_min,
        "Fwd Packet Length Mean": float(fwd_mean),
        "Bwd Packet Length Max": bwd_max,
        "Bwd Packet Length Min": bwd_min,
        "Bwd Packet Length Mean": float(bwd_mean),
        "Flow Bytes/s": float(flow_bytes_s),
        "Flow Packets/s": float(flow_pkts_s),
        "Average Packet Size": float(avg_packet_size)
    }

def flujos_a_dataframe(flujos: List[FlujoRed]) -> pd.DataFrame:
    """Convierte una lista de flujos en un DataFrame de pandas."""
    registros = [extraer_features_flujo(f) for f in flujos]
    return pd.DataFrame(registros, columns=CARACTERISTICAS_ESPERADAS)

def exportar_flujos_csv(flujos: List[FlujoRed], ruta_csv: str) -> None:
    """Exporta los flujos calculados directamente a un archivo CSV."""
    df = flujos_a_dataframe(flujos)
    df.to_csv(ruta_csv, index=False)
