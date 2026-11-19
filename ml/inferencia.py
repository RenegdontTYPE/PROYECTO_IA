import joblib
import json
import torch
import torch.nn as nn
import numpy as np
import pandas as pd
from xgboost import XGBClassifier

# 1. Replicamos la arquitectura exacta del Autoencoder para poder cargar los pesos
class Autoencoder(nn.Module):
    def __init__(self, input_dim):
        super(Autoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 12),
            nn.ReLU(True),
            nn.Linear(12, 8),
            nn.ReLU(True)
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 12),
            nn.ReLU(True),
            nn.Linear(12, input_dim)
        )

    def forward(self, x):
        x = self.encoder(x)
        x = self.decoder(x)
        return x

# 2. Clase principal que usará el Integrante 3 en main.py
class MotorInferencia:
    def __init__(self, ruta_modelos="../models/"):
        """Carga todos los modelos y escaladores una sola vez en memoria."""
        print("Iniciando Motor de Inferencia IDS...")
        
        # Cargar preprocesamiento
        self.scaler = joblib.load(f"{ruta_modelos}scaler.joblib")
        self.encoder = joblib.load(f"{ruta_modelos}label_encoder.joblib")
        
        # Cargar modelos supervisados
        self.rf_model = joblib.load(f"{ruta_modelos}rf_model.joblib")
        self.xgb_model = XGBClassifier()
        self.xgb_model.load_model(f"{ruta_modelos}xgb_model.json")
        
        # Cargar Autoencoder y umbral
        with open(f"{ruta_modelos}umbral.json", 'r') as f:
            datos_umbral = json.load(f)
            self.umbral = datos_umbral['umbral_mse']
            self.features_esperadas = datos_umbral['caracteristicas']
            
        self.input_dim = len(self.features_esperadas)
        self.ae_model = Autoencoder(self.input_dim)
        self.ae_model.load_state_dict(torch.load(f"{ruta_modelos}autoencoder.pth", weights_only=True))
        self.ae_model.eval() # Modo inferencia
        
        print("Modelos cargados correctamente. Listo para recibir flujos.")

    def evaluar_flujo(self, diccionario_flujo):
        """
        Recibe un diccionario con las características de un flujo de red.
        Retorna un diccionario con las predicciones.
        """
        # Extraer solo las variables que el modelo necesita en el orden correcto
        try:
            valores = [diccionario_flujo[feat] for feat in self.features_esperadas]
        except KeyError as e:
            return {"error": f"Falta la característica: {e}"}

        # Convertir a array y escalar
        X_nuevo = np.array(valores).reshape(1, -1)
        X_escalado = self.scaler.transform(X_nuevo)
        
        # 1. Predicción Supervisada (Random Forest y XGBoost)
        rf_pred_num = self.rf_model.predict(X_escalado)[0]
        xgb_pred_num = self.xgb_model.predict(X_escalado)[0]
        
        rf_pred_label = self.encoder.inverse_transform([rf_pred_num])[0]
        xgb_pred_label = self.encoder.inverse_transform([xgb_pred_num])[0]
        
        # 2. Detección de Anomalías (Autoencoder)
        tensor_X = torch.tensor(X_escalado, dtype=torch.float32)
        with torch.no_grad():
            reconstruccion = self.ae_model(tensor_X)
            mse = torch.mean((tensor_X - reconstruccion)**2).item()
            
        es_anomalia = mse > self.umbral

        # 3. Empaquetar resultado para el Dashboard
        return {
            "alerta_general": "SOSPECHOSO" if (rf_pred_num != 0 or es_anomalia) else "NORMAL",
            "RandomForest_Clasificacion": rf_pred_label,
            "XGBoost_Clasificacion": xgb_pred_label,
            "Autoencoder_MSE": round(mse, 4),
            "Umbral_Superado": es_anomalia
        }