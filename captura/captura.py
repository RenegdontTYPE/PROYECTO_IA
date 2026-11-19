# -*- coding: utf-8 -*-
"""
Módulo de Captura de Red (Integrante 2)
Responsable de leer paquetes desde un archivo .pcap o en vivo desde la interfaz de red usando Scapy.
"""

import os
from typing import Generator, Optional, Dict, Any
from scapy.all import PcapReader, sniff, IP, TCP, UDP

def extraer_info_paquete(pkt) -> Optional[Dict[str, Any]]:
    """
    Extrae la información fundamental de un paquete de red.
    Retorna un diccionario con los datos o None si el paquete no es IP/TCP/UDP.
    """
    if not pkt.haslayer(IP):
        return None

    capa_ip = pkt[IP]
    ip_origen = capa_ip.src
    ip_destino = capa_ip.dst
    longitud = len(pkt)
    marca_tiempo = float(pkt.time)

    puerto_origen = 0
    puerto_destino = 0
    protocolo = capa_ip.proto
    flags_tcp = ""

    if pkt.haslayer(TCP):
        capa_tcp = pkt[TCP]
        puerto_origen = capa_tcp.sport
        puerto_destino = capa_tcp.dport
        flags_tcp = str(capa_tcp.flags)
    elif pkt.haslayer(UDP):
        capa_udp = pkt[UDP]
        puerto_origen = capa_udp.sport
        puerto_destino = capa_udp.dport
    else:
        # Otros protocolos sobre IP (ej. ICMP)
        return None

    return {
        "tiempo": marca_tiempo,
        "ip_origen": ip_origen,
        "ip_destino": ip_destino,
        "puerto_origen": puerto_origen,
        "puerto_destino": puerto_destino,
        "protocolo": protocolo,
        "longitud": longitud,
        "flags_tcp": flags_tcp
    }

def leer_pcap(ruta_pcap: str) -> Generator[Dict[str, Any], None, None]:
    """
    Lee un archivo .pcap de forma eficiente (paquete por paquete)
    usando un generador (yield) para no saturar la memoria RAM.
    """
    if not os.path.exists(ruta_pcap):
        raise FileNotFoundError(f"No se encontró el archivo PCAP en: {ruta_pcap}")

    with PcapReader(ruta_pcap) as lector:
        for pkt in lector:
            info = extraer_info_paquete(pkt)
            if info is not None:
                yield info

def capturar_en_vivo(interfaz: Optional[str] = None, 
                      filtro_bpf: str = "ip and (tcp or udp)", 
                      cantidad: int = 0) -> Generator[Dict[str, Any], None, None]:
    """
    Captura paquetes en tiempo real desde la interfaz de red (ej. 'eth0' en Raspberry Pi).
    - interfaz: Nombre de la interfaz (None usa la predeterminada del sistema).
    - filtro_bpf: Filtro Berkeley Packet Filter para solo escuchar tráfico IP relevante.
    - cantidad: Cantidad de paquetes (0 = infinito hasta interrumpir).
    """
    # Usamos sniff de Scapy pasando un generador a través de una cola interna
    for pkt in sniff(iface=interfaz, filter=filtro_bpf, count=cantidad, store=False):
        info = extraer_info_paquete(pkt)
        if info is not None:
            yield info
