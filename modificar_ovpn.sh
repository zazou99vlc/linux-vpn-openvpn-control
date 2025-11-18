#!/bin/bash

# Este script modifica todos los archivos .ovpn de forma idempotente
# y proporciona un resumen final de las operaciones realizadas.

# --- CONFIGURACIÓN ---
# Array con las líneas que deben existir en los archivos.
# Si quieres añadir una nueva regla, simplemente añádela a esta lista.
declare -a directives_to_add=(
    "mssfix 1450"
    "mute-replay-warnings"
)

# --- COLORES Y CONTADORES ---
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
NC=$(tput sgr0) # No Color
total_files=0
modified_files=0
silent_mode=0

# --- MODO SILENCIOSO (Opcional) ---
# Si se ejecuta con -s o --silent, solo mostrará el resumen.
if [[ "$1" == "-s" || "$1" == "--silent" ]]; then
    silent_mode=1
fi

# --- FUNCIÓN AUXILIAR ---
# Comprueba si una línea existe en un archivo y la añade si no.
# Devuelve 1 si ha modificado el archivo, 0 si no.
ensure_line_exists() {
    local line_to_check="$1"
    local file="$2"
    # Usamos -F para tratar la cadena como texto fijo, no como regex.
    # Usamos -x para que coincida la línea completa.
    if ! grep -qFx "$line_to_check" "$file"; then
        echo "$line_to_check" >> "$file"
        return 1 # Modificado
    fi
    return 0 # Sin cambios
}

# --- BUCLE PRINCIPAL ---
if [ "$silent_mode" -eq 0 ]; then
    echo "Iniciando la verificación y modificación de archivos OVPN..."
    echo "=========================================================="
fi

while IFS= read -r file; do
    total_files=$((total_files + 1))
    file_was_modified=0

    # 1. Lógica especial para 'auth-user-pass' (reemplazo)
    if grep -q '^auth-user-pass$' "$file"; then
        sed -i 's/^auth-user-pass$/auth-user-pass pass.txt/' "$file"
        file_was_modified=1
    fi

    # 2. Lógica genérica para añadir directivas desde el array
    for directive in "${directives_to_add[@]}"; do
        ensure_line_exists "$directive" "$file"
        # $? contiene el código de retorno de la última función
        if [ $? -eq 1 ]; then
            file_was_modified=1
        fi
    done

    # 3. Actualizar contadores y mostrar estado (si no está en modo silencioso)
    if [ "$file_was_modified" -eq 1 ]; then
        modified_files=$((modified_files + 1))
        if [ "$silent_mode" -eq 0 ]; then
            printf "${YELLOW}[ MODIFICADO ]${NC} %s\n" "$file"
        fi
    else
        if [ "$silent_mode" -eq 0 ]; then
            printf "${GREEN}[ SIN CAMBIOS ]${NC} %s\n" "$file"
        fi
    fi

done < <(find . -maxdepth 1 -type f -name "*.ovpn")

# --- RESUMEN FINAL ---
echo "=========================================================="
echo "¡Proceso completado!"
echo
echo "--- RESUMEN DE LA EJECUCIÓN ---"
echo "Total de archivos .ovpn encontrados: $total_files"
echo "Archivos realmente modificados:      ${YELLOW}$modified_files${NC}"
echo "=========================================================="

# --- NOTIFICACIÓN DEL SISTEMA ---
# Comprueba si 'notify-send' está disponible antes de usarlo.
if command -v notify-send &> /dev/null; then
    # Crear el cuerpo del mensaje para la notificación
    notification_body="Total encontrados: $total_files\nArchivos modificados: $modified_files"
    
    # Enviar la notificación crítica
    notify-send --urgency=critical --icon=document-edit-symbolic "Modificación de OVPNs Completada" "$notification_body"
fi
