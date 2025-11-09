#!/bin/bash

# ==============================================================================
#          LANZADOR INTELIGENTE Y CONFIGURADOR PARA TRANSMISSION
#                   (Método GUI-Directo, sin demonio)
# ==============================================================================

# --- MODO LANZADOR ---
if [ "$1" != "--run-worker" ]; then
    SCRIPT_PATH=$(readlink -f "$0")
    if [[ "$XDG_CURRENT_DESKTOP" == *"GNOME"* ]]; then
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
# --- MODO WORKER ---
# ==============================================================================

# --- CONFIGURACIÓN ---
CONFIG_FILE="$HOME/.config/transmission/settings.json"
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PORT_FILE="$SCRIPT_DIR/forwarded_port.txt"

# --- LÓGICA DEL SCRIPT ---

# ... (Verificaciones de jq, archivos y puerto, sin cambios) ...
if ! command -v jq &> /dev/null; then
    echo "Error: La herramienta 'jq' es necesaria pero no está instalada."
    exit 1
fi
if [ ! -f "$PORT_FILE" ]; then
  echo "Error: No se encuentra el archivo del puerto ('$PORT_FILE')."
  exit 1
fi
NUEVO_PUERTO=$(cat "$PORT_FILE")
if ! [[ "$NUEVO_PUERTO" =~ ^[0-9]+$ ]]; then
    echo "Error: El contenido del archivo del puerto no es un número válido."
    exit 1
fi
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: No se encuentra el archivo de configuración en '$CONFIG_FILE'"
    exit 1
fi

echo ">>> Puerto leído del archivo: $NUEVO_PUERTO"
echo ">>> Configurando Transmission..."

# --- INICIO: BLOQUE DE EXCLUSIVIDAD MUTUA ---
echo "--> Asegurándose de que aMule esté cerrado..."
killall amule amuled 2>/dev/null
# --- FIN: BLOQUE DE EXCLUSIVIDAD MUTUA ---

# Detener la GUI de Transmission para poder modificar el archivo de forma segura.
echo "--> Deteniendo instancias anteriores de Transmission..."
killall transmission-gtk 2>/dev/null
sleep 2

# Usar 'jq' para modificar el puerto en el archivo de configuración.
echo "--> Actualizando el puerto en '$CONFIG_FILE'..."
TEMP_FILE=$(mktemp)
jq '.["peer-port"] = $new_port_int' --argjson new_port_int "$NUEVO_PUERTO" "$CONFIG_FILE" > "$TEMP_FILE"

if [ $? -eq 0 ]; then
    mv "$TEMP_FILE" "$CONFIG_FILE"
    echo "--> ¡Puerto actualizado con éxito!"
else
    echo "Error: Fallo al procesar el archivo JSON con 'jq'."
    rm -f "$TEMP_FILE"
    exit 1
fi

# Iniciar la interfaz gráfica de Transmission en segundo plano.
echo "--> Iniciando la interfaz gráfica de Transmission (GUI)..."
transmission-gtk >/dev/null 2>&1 &

echo ">>> ¡Transmission GUI iniciado con el nuevo puerto!"
exit 0
