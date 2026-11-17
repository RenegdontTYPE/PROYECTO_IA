
from pathlib import Path
from datetime import datetime, timedelta

import pandas as pd
import streamlit as st

# --------------------------------------------------
# CONFIGURACION GENERAL
# --------------------------------------------------
st.set_page_config(
    page_title="IDS Monitor",
    page_icon="🛡️",
    layout="wide"
)

BASE_DIR = Path(__file__).resolve().parent.parent
ARCHIVO_CSV = BASE_DIR / "data" / "resultados_demo.csv"

COLUMNAS = [
    "timestamp",
    "flow_id",
    "src_ip",
    "dst_ip",
    "protocol",
    "total_packets",
    "total_bytes",
    "prediction"
]


# --------------------------------------------------
# DATOS DE PRUEBA
# --------------------------------------------------
def generar_datos_demo():
    registros = []
    inicio = datetime.now().replace(microsecond=0)

    for i in range(60):
        sospechoso = (i % 9 == 0)

        registros.append({
            "timestamp": (
                inicio - timedelta(minutes=60-i)
            ).isoformat(sep=" "),
            "flow_id": f"FLOW-{i+1:03d}",
            "src_ip": f"192.168.1.{10+(i % 15)}",
            "dst_ip": "192.168.1.100",
            "protocol": "TCP" if i % 3 else "UDP",
            "total_packets": 12 + i * 3,
            "total_bytes": 900 + i * 150,
            "prediction": (
                "sospechoso" if sospechoso else "normal"
            )
        })

    return pd.DataFrame(registros)


def cargar_datos(archivo=None):
    if archivo is not None:
        return pd.read_csv(archivo)

    if ARCHIVO_CSV.exists():
        return pd.read_csv(ARCHIVO_CSV)

    return generar_datos_demo()


# --------------------------------------------------
# INTERFAZ
# --------------------------------------------------
st.title("🛡️ IDS Monitor")
st.caption(
    "Sistema de deteccion de anomalias "
    "en trafico de red | Proyecto 3"
)

st.sidebar.header("Configuracion")

archivo_subido = st.sidebar.file_uploader(
    "Cargar resultados CSV",
    type=["csv"]
)

if st.sidebar.button("Actualizar datos"):
    st.rerun()

df = cargar_datos(archivo_subido)

# Normalizar columnas
df.columns = df.columns.str.strip()

faltantes = [c for c in COLUMNAS if c not in df.columns]

if faltantes:
    st.error(
        "El archivo CSV no contiene estas columnas: "
        + ", ".join(faltantes)
    )
    st.stop()

# Preparacion
df["timestamp"] = pd.to_datetime(
    df["timestamp"], errors="coerce"
)

df["prediction"] = (
    df["prediction"]
    .astype(str)
    .str.strip()
    .str.lower()
)

df["total_packets"] = pd.to_numeric(
    df["total_packets"], errors="coerce"
)

df["total_bytes"] = pd.to_numeric(
    df["total_bytes"], errors="coerce"
)

df = df.dropna(
    subset=[
        "timestamp",
        "total_packets",
        "total_bytes"
    ]
)

df = df[
    df["prediction"].isin(["normal", "sospechoso"])
].copy()

df = df.sort_values("timestamp")

# --------------------------------------------------
# FILTROS
# --------------------------------------------------
st.sidebar.subheader("Filtros")

protocolos = st.sidebar.multiselect(
    "Protocolos",
    options=sorted(df["protocol"].dropna().unique()),
    default=sorted(df["protocol"].dropna().unique())
)

df_filtrado = df[df["protocol"].isin(protocolos)]

# --------------------------------------------------
# INDICADORES
# --------------------------------------------------
total = len(df_filtrado)

normales = (
    df_filtrado["prediction"] == "normal"
).sum()

sospechosos = (
    df_filtrado["prediction"] == "sospechoso"
).sum()

tasa_alertas = (
    sospechosos / total * 100 if total else 0
)

col1, col2, col3, col4 = st.columns(4)

col1.metric("Flujos analizados", total)
col2.metric("Normales", normales)
col3.metric("Sospechosos", sospechosos)
col4.metric("Alertas (%)", f"{tasa_alertas:.1f}%")

# --------------------------------------------------
# ALERTAS
# --------------------------------------------------
st.subheader("Estado del monitoreo")

if sospechosos > 0:
    st.warning(
        f"Se identificaron {sospechosos} "
        "flujos clasificados como sospechosos."
    )
else:
    st.success(
        "No se identificaron flujos sospechosos "
        "en los registros seleccionados."
    )

# --------------------------------------------------
# GRAFICAS
# --------------------------------------------------
st.subheader("Analisis del trafico")

col_g1, col_g2 = st.columns(2)

with col_g1:
    st.write("Distribucion de clasificaciones")

    distribucion = (
        df_filtrado["prediction"]
        .value_counts()
        .reindex(
            ["normal", "sospechoso"],
            fill_value=0
        )
    )

    st.bar_chart(distribucion)

with col_g2:
    st.write("Actividad por intervalo de tiempo")

    if not df_filtrado.empty:
        actividad = (
            df_filtrado
            .set_index("timestamp")
            .groupby([
                pd.Grouper(freq="5min"),
                "prediction"
            ])
            .size()
            .unstack(fill_value=0)
            .reindex(
                columns=["normal", "sospechoso"],
                fill_value=0
            )
        )

        st.line_chart(actividad)
    else:
        st.info("Sin datos para graficar.")

# --------------------------------------------------
# TABLA
# --------------------------------------------------
st.subheader("Registro de flujos")

st.dataframe(
    df_filtrado.sort_values(
        "timestamp", ascending=False
    ),
    use_container_width=True,
    hide_index=True
)

# --------------------------------------------------
# EXPORTAR
# --------------------------------------------------
csv = df_filtrado.to_csv(index=False).encode("utf-8")

st.download_button(
    "Descargar registros CSV",
    data=csv,
    file_name="registros_ids.csv",
    mime="text/csv"
)

st.caption(
    "Version de desarrollo. Los datos de demostracion "
    "son simulados y no representan detecciones reales."
)
