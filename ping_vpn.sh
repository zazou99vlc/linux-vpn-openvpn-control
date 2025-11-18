#!/bin/bash

# ==============================================================================
#             LANZADOR INTELIGENTE DE PRUEBA DE VPN
# ==============================================================================

# --- MODO LANZADOR (Inicia el script en un nuevo terminal) ---
if [ "$1" != "--run-worker" ]; then
    SCRIPT_PATH=$(readlink -f "$0")
    # Guarda los argumentos originales para pasarlos al modo trabajador, excluyendo el nombre del script.
    # Shift ignora el primer argumento (el nombre del script).
    shift 1
    WORKER_ARGS="$@"
    
    # Intenta detectar el entorno de escritorio para usar el comando de terminal correcto.
    if [[ "$XDG_CURRENT_DESKTOP" == *"GNOME"* ]]; then
        # GNOME (usa 'bash -c' para pasar comandos y mantener la ventana abierta)
        gnome-terminal -- bash -c "'$SCRIPT_PATH' --run-worker $WORKER_ARGS; echo; read -p '>>> Proceso finalizado. Presiona Enter para cerrar esta ventana.'"
        exit 0
    elif [[ "$XDG_CURRENT_DESKTOP" == *"XFCE"* ]]; then
        # XFCE (usa '--hold' para mantener la ventana abierta)
        xfce4-terminal --hold -e "'$SCRIPT_PATH' --run-worker $WORKER_ARGS"
        exit 0
    elif [[ "$XDG_CURRENT_DESKTOP" == *"KDE"* ]]; then
        # KDE (usa 'konsole' y '--hold' para mantener la ventana abierta)
        konsole --hold -e "'$SCRIPT_PATH' --run-worker $WORKER_ARGS"
        exit 0
    else
        echo "Error: Entorno de escritorio no compatible o no detectado ('$XDG_CURRENT_DESKTOP')."
        echo "Lanzando en terminal actual. Presiona Enter para cerrar al finalizar."
        # Si no se detecta, lo ejecuta directamente en el terminal actual y añade un 'read'
        # para que el usuario pueda ver los resultados.
        bash -c "'$SCRIPT_PATH' --run-worker $WORKER_ARGS; echo; read -p '>>> Presiona Enter para finalizar.'"
        exit 0
    fi
fi

# ==============================================================================
# --- MODO TRABAJADOR (Contiene la lógica de tu script original) ---
# ==============================================================================

# --- PREPARACIÓN ---
# Elimina el argumento de control para que el script pueda procesar los argumentos originales.
shift 1
export LC_NUMERIC="C"
# Si no se da un argumento (después del shift), usa el directorio actual.
OVPN_DIR=${1:-.}

# Comprueba si el directorio es válido y contiene archivos .ovpn.
if ! [ -d "$OVPN_DIR" ] || ! ls "$OVPN_DIR"/*.ovpn &>/dev/null; then
    echo "Error: El directorio '$OVPN_DIR' no existe o no contiene archivos .ovpn."
    # El terminal permanecerá abierto gracias a la lógica del lanzador.
    exit 1
fi

echo "Analizando archivos .ovpn en: $(realpath "$OVPN_DIR")"
echo "------------------------------------------------------------------"

# --- 1. Extraer Hosts y Ciudades ---
declare -A host_to_city
for file in "$OVPN_DIR"/*.ovpn; do
    # Intenta extraer la ciudad del nombre del archivo, usando '-' como delimitador.
    city=$(basename "$file" .ovpn | cut -d'-' -f3)
    [ -z "$city" ] && city="Desconocida"

    file_hosts=$(grep -E '^remote\s' "$file" | awk '{print $2}')
    for host in $file_hosts; do
        if [[ -z "${host_to_city[$host]}" ]]; then
            host_to_city["$host"]=$city
        fi
    done
done

HOSTS="${!host_to_city[@]}"

if [ -z "$HOSTS" ]; then
    echo "No se encontraron hosts en los archivos .ovpn."
    exit 1
fi

echo "Se encontraron ${#host_to_city[@]} servidores únicos. Realizando ping..."
echo ""

# --- 2. Realizar Ping ---
declare -A responsive_hosts
unresponsive_hosts=()

for host in $HOSTS; do
    # Ping con 2 paquetes (-c 2) y tiempo de espera de 1.5 segundos (-W 1.5)
    ping_result=$(ping -c 2 -W 1.5 "$host" 2>/dev/null)
    if [ $? -eq 0 ]; then
        # Extrae la latencia media (awk -F '/' '{print $5}')
        latency=$(echo "$ping_result" | tail -n 1 | awk -F '/' '{print $5}')
        responsive_hosts["$host"]=$latency
    else
        unresponsive_hosts+=("$host")
    fi
done

# --- 3. Mostrar Resultados ---
echo "✅ Servidores Disponibles (ordenados del más rápido al más lento):"
printf "  %-15s | %-25s | %s\n" "CIUDAD" "SERVIDOR" "LATENCIA"
printf "  %-15s | %-25s | %s\n" "---------------" "-------------------------" "----------"

if [ ${#responsive_hosts[@]} -gt 0 ]; then
    # Genera los resultados, los ordena numéricamente y los formatea.
    (for host in "${!responsive_hosts[@]}"; do
        printf "%.3f %s\n" "${responsive_hosts[$host]}" "$host"
    done) | sort -n | while read -r latency host; do
        city=${host_to_city[$host]:-Desconocida}
        formatted_latency=$(printf "%.2f" "$latency")
        printf "  %-15s | %-25s | %s ms\n" "$city" "$host" "$formatted_latency"
    done
else
    echo "  Ningún servidor respondió al ping."
fi

echo ""
echo "❌ Servidores Caídos o No Encontrados:"
printf "  %-15s | %s\n" "CIUDAD" "SERVIDOR"
printf "  %-15s | %s\n" "---------------" "-------------------------"
if [ ${#unresponsive_hosts[@]} -gt 0 ]; then
    IFS=$'\n' sorted_unresponsive=($(sort <<<"${unresponsive_hosts[*]}"))
    unset IFS

    for host in "${sorted_unresponsive[@]}"; do
        city=${host_to_city[$host]:-Desconocida}
        printf "  %-15s | %s\n" "$city" "$host"
    done
else
    echo "  ¡Todos los servidores respondieron!"
fi
echo "------------------------------------------------------------------"

# El terminal permanecerá abierto gracias a la lógica del lanzador.
# No necesitamos un 'read' adicional aquí.
exit 0
