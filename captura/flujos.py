# -*- coding: utf-8 -*-
"""
Módulo de Gestión de Flujos de Red (Integrante 2)
Agrupa paquetes individuales en conversaciones bidireccionales (flujos de 5 tuplas).
"""

from typing import Dict, List, Tuple, Optional, Any

class FlujoRed:
    """
    Representa una conversación bidireccional entre dos equipos de red.
    """
    def __init__(self, primer_paquete: Dict[str, Any]):
        # La dirección del primer paquete establece el sentido 'Forward' (hacia adelante)
        self.ip_origen = primer_paquete["ip_origen"]
        self.ip_destino = primer_paquete["ip_destino"]
        self.puerto_origen = primer_paquete["puerto_origen"]
        self.puerto_destino = primer_paquete["puerto_destino"]
        self.protocolo = primer_paquete["protocolo"]

        self.tiempo_inicio = primer_paquete["tiempo"]
        self.tiempo_ultimo = primer_paquete["tiempo"]

        # Listas para almacenar las longitudes en bytes de los paquetes
        self.fwd_paquetes: List[int] = [primer_paquete["longitud"]]
        self.bwd_paquetes: List[int] = []

        # Estado de terminación (ej. banderas TCP FIN o RST)
        self.finalizado = "F" in primer_paquete.get("flags_tcp", "") or "R" in primer_paquete.get("flags_tcp", "")

    def agregar_paquete(self, paquete: Dict[str, Any]) -> None:
        """
        Agrega un nuevo paquete al flujo identificando si va hacia adelante (Fwd) o hacia atrás (Bwd).
        """
        self.tiempo_ultimo = paquete["tiempo"]
        
        # Verificar dirección del paquete
        if paquete["ip_origen"] == self.ip_origen and paquete["puerto_origen"] == self.puerto_origen:
            self.fwd_paquetes.append(paquete["longitud"])
        else:
            self.bwd_paquetes.append(paquete["longitud"])

        # Si el paquete tiene bandera FIN o RST, marcamos el flujo para cierre
        flags = paquete.get("flags_tcp", "")
        if "F" in flags or "R" in flags:
            self.finalizado = True

    def ha_expirado(self, tiempo_actual: float, timeout_segundos: float = 15.0) -> bool:
        """Determina si el flujo terminó por inactividad o cierre formal."""
        if self.finalizado:
            return True
        return (tiempo_actual - self.tiempo_ultimo) >= timeout_segundos


class GestorFlujos:
    """
    Administra la colección de flujos activos en memoria.
    """
    def __init__(self, timeout_segundos: float = 15.0):
        self.timeout_segundos = timeout_segundos
        # Diccionario clave canónica -> Objeto FlujoRed
        self.flujos_activos: Dict[Tuple, FlujoRed] = {}

    def _obtener_clave_canonica(self, pkt: Dict[str, Any]) -> Tuple:
        """
        Genera una clave que sea idéntica sin importar quién envía y quién responde.
        """
        ip1, ip2 = sorted([pkt["ip_origen"], pkt["ip_destino"]])
        p1, p2 = sorted([pkt["puerto_origen"], pkt["puerto_destino"]])
        return (ip1, ip2, p1, p2, pkt["protocolo"])

    def procesar_paquete(self, pkt: Dict[str, Any]) -> List[FlujoRed]:
        """
        Recibe un paquete, lo asocia a su flujo y retorna los flujos que hayan finalizado.
        """
        clave = self._obtener_clave_canonica(pkt)
        flujos_terminados: List[FlujoRed] = []

        if clave in self.flujos_activos:
            flujo = self.flujos_activos[clave]
            flujo.agregar_paquete(pkt)
            if flujo.finalizado:
                flujos_terminados.append(flujo)
                del self.flujos_activos[clave]
        else:
            self.flujos_activos[clave] = FlujoRed(pkt)

        # Chequear expiración periódica de flujos inactivos
        tiempo_actual = pkt["tiempo"]
        claves_a_borrar = []
        for k, f in self.flujos_activos.items():
            if f.ha_expirado(tiempo_actual, self.timeout_segundos):
                flujos_terminados.append(f)
                claves_a_borrar.append(k)

        for k in claves_a_borrar:
            if k in self.flujos_activos:
                del self.flujos_activos[k]

        return flujos_terminados

    def vaciar_todos(self) -> List[FlujoRed]:
        """Fuerza la finalización de todos los flujos pendientes (útil al terminar un archivo PCAP)."""
        terminados = list(self.flujos_activos.values())
        self.flujos_activos.clear()
        return terminados
