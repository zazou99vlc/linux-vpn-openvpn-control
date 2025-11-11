#!/bin/bash

# ==============================================================================
# 	 	 LANZADOR INTELIGENTE Y CONFIGURADOR PARA AMULE
# ==============================================================================

# --- MODO LANZADOR (¡CORREGIDO para XFCE!) ---
if [ "$1" != "--run-worker" ]; then
    SCRIPT_PATH=$(readlink -f "$0")
    
    # Capturamos las variables de entorno gráfico del lanzador.
    DISPLAY_ENV="$DISPLAY"
    XAUTH_ENV="$XAUTHORITY"

    if [[ "$XDG_CURRENT_DESKTOP" == *"GNOME"* ]]; then
        # GNOME: Pasa las variables y usa bash -c para la pausa.
        gnome-terminal -- bash -c "export DISPLAY='$DISPLAY_ENV'; export XAUTHORITY='$XAUTH_ENV'; '$SCRIPT_PATH' --run-worker; echo; read -p '>>> Proceso finalizado. Presiona Enter para cerrar esta ventana.'"
        exit 0
    elif [[ "$XDG_CURRENT_DESKTOP" == *"XFCE"* ]]; then
        # XFCE: Usa xfce4-terminal, que hereda mejor el DISPLAY que la ejecución directa.
        # Esto permite que gio launch funcione mejor en el Worker.
        xfce4-terminal --hold -e "bash -c 'export DISPLAY=\"$DISPLAY_ENV\"; export XAUTHORITY=\"$XAUTH_ENV\"; \"$SCRIPT_PATH\" --run-worker'"
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

# --- INICIO: DETECCIÓN DEL ARCHIVO .desktop (NUEVO BLOQUE) ---
LAUNCHER_NAMES=("amule.desktop" "amule-gui.desktop")
BINARIES_KILL=("amule" "amuled")
AMULE_LAUNCHER=""

echo ">>> Buscando archivo lanzador (.desktop) de aMule..."

for NAME in "${LAUNCHER_NAMES[@]}"; do
    if [ -f "$HOME/.local/share/applications/$NAME" ]; then
        AMULE_LAUNCHER="$HOME/.local/share/applications/$NAME"
        break
    elif [ -f "/usr/share/applications/$NAME" ]; then
        AMULE_LAUNCHER="/usr/share/applications/$NAME"
        break
    fi
done

if [ -z "$AMULE_LAUNCHER" ]; then
    echo "Error: No se encontró ningún lanzador (.desktop) conocido de aMule."
    # En aMule, si no encontramos el lanzador, intentamos la ejecución directa como fallback,
    # ya que el binario es muy consistente (amule).
    if command -v amule &> /dev/null; then
        echo "AVISO: Se usará el binario directo 'amule' para el lanzamiento."
        AMULE_LAUNCHER="amule"
    else
        exit 1
    fi
fi
echo ">>> Lanzador/Binario detectado: $AMULE_LAUNCHER"
# --- FIN: DETECCIÓN DEL ARCHIVO .desktop ---


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
killall "${BINARIES_KILL[@]}" 2>/dev/null
sleep 2

# Usar 'sed' para modificar los puertos en el archivo de configuración.
echo "--> Actualizando puerto TCP..."
sed -i "s/^Port=.*/Port=$NUEVO_PUERTO/" "$AMULE_CONFIG_FILE"
echo "--> Actualizando puerto UDP..."
sed -i "s/^UDPPort=.*/UDPPort=$NUEVO_PUERTO/" "$AMULE_CONFIG_FILE"
echo "--> ¡Configuración actualizada!"

# Iniciar la GUI de aMule usando el lanzador de escritorio.
echo "--> Iniciando la interfaz gráfica de aMule (GUI) con: $AMULE_LAUNCHER..."

# Comprobamos si es un .desktop o el binario directo
if [[ "$AMULE_LAUNCHER" == *".desktop"* ]]; then
    # Lanzamiento vía .desktop (el método más fiable)
    gio launch "$AMULE_LAUNCHER" >/dev/null 2>&1 &
    if [ $? -ne 0 ]; then
        echo "AVISO: gio launch falló. Intentando con xdg-open..."
        xdg-open "$AMULE_LAUNCHER" >/dev/null 2>&1 &
    fi
else
    # Fallback: Lanzamiento directo con setsid, que es robusto para aMule
    setsid "$AMULE_LAUNCHER" >/dev/null 2>&1 &
fi

echo ">>> ¡aMule GUI iniciado con el nuevo puerto!"

# ----------------------------------------------------------------------
# AÑADIDO: Espera unos segundos para asegurar que el usuario pueda leer 
# los mensajes finales antes de que el lanzador tome el control y pause.
sleep 3
# ----------------------------------------------------------------------

exit 0
