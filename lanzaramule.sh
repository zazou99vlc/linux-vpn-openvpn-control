#!/bin/bash

# ==============================================================================
# 	 	 LANZADOR INTELIGENTE Y CONFIGURADOR PARA AMULE
# ==============================================================================

# --- MODO LANZADOR ---
if [ "$1" != "--run-worker" ]; then
    SCRIPT_PATH=$(readlink -f "$0")
    if [[ "$XDG_CURRENT_DESKTOP" == *"GNOME"* ]]; then
        # La pausa (read -p) se mantiene aquí, pero ahora el trabajador esperará 3s.
        gnome-terminal -- bash -c "'$SCRIPT_PATH' --run-worker; echo; read -p '>>> Proceso finalizado. Presiona Enter para cerrar esta ventana.'"
        exit 0
    elif [[ "$XDG_CURRENT_DESKTOP" == *"XFCE"* ]]; then
        xfce4-terminal --hold -e "'$SCRIPT_PATH' --run-worker"
        exit 0
    else
        echo "Error: Entorno de escritorio no compatible ('$XDG_CURRENT_DESKTOP')."
        exit 1
    fi
fi

# ==============================================================================
# --- MODO TRABAJADOR ---
# ==============================================================================

# --- CONFIGURACIÓN ---
AMULE_CONFIG_FILE="$HOME/.aMule/amule.conf"
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PORT_FILE="$SCRIPT_DIR/forwarded_port.txt"

# --- LÓGICA DEL SCRIPT ---

# ... (Verificaciones de archivos y puerto, sin cambios) ...
if [ ! -f "$PORT_FILE" ]; then
    echo "Error: No se encuentra el archivo del puerto ('$PORT_FILE')."
    exit 1
fi
NUEVO_PUERTO=$(cat "$PORT_FILE")
if ! [[ "$NUEVO_PUERTO" =~ ^[0-9]+$ ]]; then
    echo "Error: El contenido del archivo del puerto no es un número válido."
    exit 1
fi
if [ ! -f "$AMULE_CONFIG_FILE" ]; then
    echo "Error: No se encuentra el archivo de configuración en '$AMULE_CONFIG_FILE'"
    exit 1
fi

echo ">>> Puerto leído del archivo: $NUEVO_PUERTO"
echo ">>> Configurando aMule..."

# --- INICIO: BLOQUE DE EXCLUSIVIDAD MUTUA ---
echo "--> Asegurándose de que Transmission esté cerrado..."
killall transmission-gtk transmission-daemon 2>/dev/null
# --- FIN: BLOQUE DE EXCLUSIVIDAD MUTUA ---

# Detener cualquier proceso de aMule en ejecución.
echo "--> Deteniendo instancias anteriores de aMule..."
killall amule amuled 2>/dev/null
sleep 2

# Usar 'sed' para modificar los puertos en el archivo de configuración.
echo "--> Actualizando puerto TCP..."
sed -i "s/^Port=.*/Port=$NUEVO_PUERTO/" "$AMULE_CONFIG_FILE"
echo "--> Actualizando puerto UDP..."
sed -i "s/^UDPPort=.*/UDPPort=$NUEVO_PUERTO/" "$AMULE_CONFIG_FILE"
echo "--> ¡Configuración actualizada!"

# Iniciar la GUI de aMule desvinculada de la terminal (usando nohup).
echo "--> Iniciando la interfaz gráfica de aMule (GUI)..."
nohup amule >/dev/null 2>&1 &

echo ">>> ¡aMule GUI iniciado con el nuevo puerto!"

# ----------------------------------------------------------------------
# AÑADIDO: Espera unos segundos para asegurar que el usuario pueda leer 
# los mensajes finales antes de que el lanzador tome el control y pause.
sleep 3
# ----------------------------------------------------------------------

exit 0
