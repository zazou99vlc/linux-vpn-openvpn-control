#!/bin/bash

# ==============================================================================
# 	 	 LANZADOR INTELIGENTE Y CONFIGURADOR PARA TRANSMISSION
# 	 	 	 	 (Método GUI-Directo, sin demonio)
# ==============================================================================

# --- MODO LANZADOR (Sintaxis XFCE corregida) ---
if [ "$1" != "--run-worker" ]; then
    SCRIPT_PATH=$(readlink -f "$0")
    # Capturamos las variables de entorno gráfico del lanzador.
    DISPLAY_ENV="$DISPLAY"
    XAUTH_ENV="$XAUTHORITY"

    if [[ "$XDG_CURRENT_DESKTOP" == *"GNOME"* ]]; then
        # GNOME (Mantiene la pausa de terminal)
        gnome-terminal -- bash -c "export DISPLAY='$DISPLAY_ENV'; export XAUTHORITY='$XAUTH_ENV'; '$SCRIPT_PATH' --run-worker; echo; read -p '>>> Proceso finalizado. Presiona Enter para cerrar esta ventana.'"
        exit 0
    elif [[ "$XDG_CURRENT_DESKTOP" == *"XFCE"* ]]; then
        # XFCE (¡SINTAXIS CORREGIDA! Lanzamiento directo sin terminal anidada.)
        "$SCRIPT_PATH" --run-worker
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

# --- INICIO: DETECCIÓN DEL ARCHIVO .desktop (Para Killall y Lanzamiento) ---
# Usamos el binario para Killall y el .desktop para el lanzamiento (como en V6.0).
LAUNCHER_NAMES=("transmission-gtk.desktop" "transmission-qt.desktop" "transmission.desktop")
BINARIES_KILL=("transmission-gtk" "transmission-qt" "transmission")
TRANSMISSION_LAUNCHER=""

echo ">>> Buscando archivo lanzador (.desktop) de Transmission..."

for NAME in "${LAUNCHER_NAMES[@]}"; do
    if [ -f "$HOME/.local/share/applications/$NAME" ]; then
        TRANSMISSION_LAUNCHER="$HOME/.local/share/applications/$NAME"
        break
    elif [ -f "/usr/share/applications/$NAME" ]; then
        TRANSMISSION_LAUNCHER="/usr/share/applications/$NAME"
        break
    fi
done

if [ -z "$TRANSMISSION_LAUNCHER" ]; then
    echo "Error: No se encontró ningún lanzador (.desktop) conocido de Transmission."
    exit 1
fi
echo ">>> Lanzador detectado: $TRANSMISSION_LAUNCHER"
# --- FIN: DETECCIÓN DEL ARCHIVO .desktop ---


# --- LÓGICA DEL SCRIPT ---
# ... (Verificaciones de jq, archivos y puerto) ...
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
killall "${BINARIES_KILL[@]}" 2>/dev/null # Usa la lista de binarios para killall
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

# Iniciar la interfaz gráfica de Transmission usando el lanzador de escritorio.
echo "--> Iniciando Transmission GUI con el lanzador: $TRANSMISSION_LAUNCHER..."
gio launch "$TRANSMISSION_LAUNCHER" >/dev/null 2>&1 &
if [ $? -ne 0 ]; then
    echo "AVISO: gio launch falló. Intentando con xdg-open..."
    xdg-open "$TRANSMISSION_LAUNCHER" >/dev/null 2>&1 &
fi

echo ">>> ¡Transmission GUI iniciado con el nuevo puerto!"
exit 0
