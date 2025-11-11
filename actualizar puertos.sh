#!/bin/bash

# ==============================================================================
# 	 SCRIPT PARA ACTUALIZAR LOS PUERTOS DE TRANSMISSION Y AMULE
# ==============================================================================
#
# Versión 4.0: Todas las notificaciones finales (éxito o fracaso) son críticas
# para asegurar que el resultado sea siempre visible.
#
# ==============================================================================

# --- CONFIGURACIÓN DE RUTAS ---
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PORT_FILE="$SCRIPT_DIR/forwarded_port.txt"
TRANSMISSION_CONFIG_FILE="$HOME/.config/transmission/settings.json"
AMULE_CONFIG_FILE="$HOME/.aMule/amule.conf"

# --- BANDERAS DE ESTADO ---
AMULE_UPDATED=0
TRANSMISSION_UPDATED=0

# --- VERIFICACIONES INICIALES ---
if [ ! -f "$PORT_FILE" ]; then
    notify-send --urgency=critical "Error Crítico" "No se encontró el archivo de puerto en '$PORT_FILE'."
    exit 1
fi
NUEVO_PUERTO=$(cat "$PORT_FILE")
if ! [[ "$NUEVO_PUERTO" =~ ^[0-9]+$ ]]; then
    notify-send --urgency=critical "Error Crítico" "El contenido de '$PORT_FILE' no es un número válido."
    exit 1
fi
if ! command -v jq &> /dev/null; then
    notify-send --urgency=critical "Error Crítico" "La herramienta 'jq' es necesaria pero no está instalada."
    exit 1
fi

# --- ACTUALIZACIÓN DE TRANSMISSION ---
if [ -f "$TRANSMISSION_CONFIG_FILE" ]; then
    killall transmission-gtk transmission-qt transmission-daemon 2>/dev/null; sleep 1
    TEMP_FILE=$(mktemp)
    jq '.["peer-port"] = $new_port_int' --argjson new_port_int "$NUEVO_PUERTO" "$TRANSMISSION_CONFIG_FILE" > "$TEMP_FILE"
    if [ $? -eq 0 ] && [ -s "$TEMP_FILE" ]; then
        mv "$TEMP_FILE" "$TRANSMISSION_CONFIG_FILE"
        TRANSMISSION_UPDATED=1
    else
        notify-send --urgency=critical "Error en Transmission" "Fallo al procesar el archivo de configuración. El puerto no se actualizó."
        rm -f "$TEMP_FILE"
    fi
else
    notify-send --urgency=normal "Aviso de Configuración" "No se encontró el archivo de Transmission. Se omitirá su actualización."
fi

# --- ACTUALIZACIÓN DE AMULE ---
if [ -f "$AMULE_CONFIG_FILE" ]; then
    killall amule amuled 2>/dev/null; sleep 1
    sed -i "s/^Port=.*/Port=$NUEVO_PUERTO/" "$AMULE_CONFIG_FILE"
    sed -i "s/^UDPPort=.*/UDPPort=$NUEVO_PUERTO/" "$AMULE_CONFIG_FILE"
    AMULE_UPDATED=1
else
    notify-send --urgency=normal "Aviso de Configuración" "No se encontró el archivo de aMule. Se omitirá su actualización."
fi

# --- LÓGICA DE NOTIFICACIÓN FINAL DINÁMICA ---
declare -a updated_apps
if [ "$AMULE_UPDATED" -eq 1 ]; then updated_apps+=("aMule"); fi
if [ "$TRANSMISSION_UPDATED" -eq 1 ]; then updated_apps+=("Transmission"); fi

num_updated=${#updated_apps[@]}

if [ "$num_updated" -gt 0 ]; then
    if [ "$num_updated" -eq 2 ]; then
        program_list="${updated_apps[0]} y ${updated_apps[1]}"
    else
        program_list="${updated_apps[0]}"
    fi
    TITLE="Actualización Completada"
    MESSAGE="Se actualizaron los puertos para: <b>$program_list</b> al puerto <b>$NUEVO_PUERTO</b>."
    notify-send --urgency=critical "$TITLE" "$MESSAGE"
else
    TITLE="No se realizaron cambios"
    MESSAGE="No se pudo actualizar el puerto para ninguna aplicación. Revisa los avisos anteriores."
    # CORRECCIÓN: La urgencia se cambia a crítica para asegurar la visibilidad del resultado.
    notify-send --urgency=critical "$TITLE" "$MESSAGE"
fi

exit 0
