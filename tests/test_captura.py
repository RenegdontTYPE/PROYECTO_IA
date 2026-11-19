# -*- coding: utf-8 -*-
"""
Prueba de Integración: Módulo de Captura -> Flujos -> Características -> Motor ML
Verifica que el Integrante 2 cumpla exactamente con el contrato requerido por el Integrante 1.
"""

import os
import sys
import unittest

# Asegurar importación de módulos del proyecto
directorio_raiz = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if directorio_raiz not in sys.path:
    sys.path.insert(0, directorio_raiz)

from captura.captura import leer_pcap
from captura.flujos import GestorFlujos
from captura.extraer_features import extraer_features_flujo, CARACTERISTICAS_ESPERADAS
from ml.inferencia import MotorInferencia

class TestCapturaFlujos(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ruta_pcap = os.path.join(directorio_raiz, "data", "captura_prueba.pcap")
        cls.ruta_models = os.path.join(directorio_raiz, "models") + "/"
        cls.motor = MotorInferencia(ruta_modelos=cls.ruta_models)

    def test_pcap_existe(self):
        """Verifica que exista el archivo PCAP de prueba."""
        self.assertTrue(os.path.exists(self.ruta_pcap), "El archivo captura_prueba.pcap debe existir en data/")

    def test_extraccion_15_caracteristicas(self):
        """Verifica que cada flujo contenga exactamente las 15 columnas del modelo."""
        gestor = GestorFlujos()
        flujos = []
        for pkt in leer_pcap(self.ruta_pcap):
            flujos.extend(gestor.procesar_paquete(pkt))
        flujos.extend(gestor.vaciar_todos())

        self.assertGreater(len(flujos), 0, "Debe reconstruirse al menos 1 flujo de red.")

        for f in flujos:
            caracteristicas = extraer_features_flujo(f)
            # 1. Comprobar que no falte ninguna variable
            for col in CARACTERISTICAS_ESPERADAS:
                self.assertIn(col, caracteristicas, f"Falta la columna requerida: {col}")
            
            # 2. Comprobar que los tipos sean numéricos
            for k, v in caracteristicas.items():
                self.assertIsInstance(v, (int, float), f"La columna {k} debe ser un valor numérico.")

    def test_compatibilidad_con_motor_inferencia(self):
        """Verifica que el MotorInferencia de Steven pueda evaluar los flujos sin errores."""
        gestor = GestorFlujos()
        flujos = []
        for pkt in leer_pcap(self.ruta_pcap):
            flujos.extend(gestor.procesar_paquete(pkt))
        flujos.extend(gestor.vaciar_todos())

        for f in flujos:
            feat = extraer_features_flujo(f)
            resultado = self.motor.evaluar_flujo(feat)
            self.assertNotIn("error", resultado, f"El motor de inferencia devolvió error: {resultado.get('error')}")
            self.assertIn("alerta_general", resultado)
            self.assertIn("RandomForest_Clasificacion", resultado)
            self.assertIn("XGBoost_Clasificacion", resultado)

if __name__ == "__main__":
    unittest.main()
