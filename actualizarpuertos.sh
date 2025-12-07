#!/bin/bash

# ==============================================================================
# 	 SCRIPT PARA ACTUALIZAR LOS PUERTOS DE TRANSMISSION Y AMULE
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

# --- DETECCIÓN Y PARADA INTELIGENTE DE PROCESOS ---
RUNNING_APPS_FILE=$(mktemp)
APPS_TO_CHECK=("transmission-gtk" "transmission-qt" "transmission-daemon" "amule" "amuled")

# Detectamos qué está corriendo y lo guardamos
for app in "${APPS_TO_CHECK[@]}"; do
    # Usamos killall -0 para comprobar si el proceso existe y podemos enviarle señales
    if killall -0 "$app" 2>/dev/null; then
        echo "$app" >> "$RUNNING_APPS_FILE"
    fi
done

# Cerramos SOLO lo que estaba corriendo
if [ -s "$RUNNING_APPS_FILE" ]; then
    while read -r app_to_kill; do
        killall "$app_to_kill" 2>/dev/null
    done < "$RUNNING_APPS_FILE"

    # Espera activa hasta que se cierren esos procesos específicos
    while true; do
        still_running=0
        while read -r app_check; do
            if killall -0 "$app_check" 2>/dev/null; then
                still_running=1
                break
            fi
        done < "$RUNNING_APPS_FILE"
        
        if [ "$still_running" -eq 0 ]; then
            break
        fi
        sleep 1
    done
fi

# --- ACTUALIZACIÓN DE TRANSMISSION ---
if [ -f "$TRANSMISSION_CONFIG_FILE" ]; then
    
    TEMP_FILE=$(mktemp)
    # jq crea un archivo nuevo con los permisos del usuario que ejecuta el script
    jq '.["peer-port"] = $new_port_int' --argjson new_port_int "$NUEVO_PUERTO" "$TRANSMISSION_CONFIG_FILE" > "$TEMP_FILE"
    
    if [ $? -eq 0 ] && [ -s "$TEMP_FILE" ]; then
        mv "$TEMP_FILE" "$TRANSMISSION_CONFIG_FILE"
        TRANSMISSION_UPDATED=1
        
        # --- FIX DE PERMISOS (Solo si se ejecuta con sudo) ---
        if [ -n "$SUDO_USER" ]; then
            chown "$SUDO_USER":"$SUDO_USER" "$TRANSMISSION_CONFIG_FILE"
        fi
    else
        notify-send --urgency=critical "Error en Transmission" "Fallo al procesar el archivo de configuración."
        rm -f "$TEMP_FILE"
    fi
else
    notify-send --urgency=normal "Aviso de Configuración" "No se encontró el archivo de Transmission."
fi

# --- ACTUALIZACIÓN DE AMULE ---
if [ -f "$AMULE_CONFIG_FILE" ]; then
    
    # sed -i edita in-place, pero a veces cambia el propietario si se hace como root
    sed -i "s/^Port=.*/Port=$NUEVO_PUERTO/" "$AMULE_CONFIG_FILE"
    sed -i "s/^UDPPort=.*/UDPPort=$NUEVO_PUERTO/" "$AMULE_CONFIG_FILE"
    AMULE_UPDATED=1

    # --- FIX DE PERMISOS (Solo si se ejecuta con sudo) ---
    if [ -n "$SUDO_USER" ]; then
        chown "$SUDO_USER":"$SUDO_USER" "$AMULE_CONFIG_FILE"
    fi
else
    notify-send --urgency=normal "Aviso de Configuración" "No se encontró el archivo de aMule."
fi

# --- LÓGICA DE NOTIFICACIÓN FINAL ---
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
    MESSAGE="No se pudo actualizar el puerto para ninguna aplicación."
    notify-send --urgency=critical "$TITLE" "$MESSAGE"
fi
sleep 30
# --- RESTAURACIÓN DE PROCESOS ---
if [ -s "$RUNNING_APPS_FILE" ]; then
    while read -r app_to_restore; do
        # Ejecutamos directo (usuario normal) y desvinculamos del script
        nohup "$app_to_restore" > /dev/null 2>&1 & disown
    done < "$RUNNING_APPS_FILE"
fi
rm -f "$RUNNING_APPS_FILE"

exit 0
