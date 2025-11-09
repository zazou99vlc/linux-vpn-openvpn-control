#!/bin/bash

# Este script modifica todos los archivos .ovpn en el directorio actual.

echo "Iniciando la modificación de archivos OVPN..."

# Buscar todos los archivos .ovpn en el directorio actual
find . -maxdepth 1 -type f -name "*.ovpn" | while read -r file; do
    echo "Procesando archivo: $file"

    # 1. Modificar la línea 'auth-user-pass'
    # 'sed -i' edita el archivo en su lugar (in-place)
    # 's/patron/reemplazo/' busca el patrón y lo reemplaza
    # El patrón busca la línea 'auth-user-pass' y la reemplaza con 'auth-user-pass pass.txt'
    sed -i 's/auth-user-pass/auth-user-pass pass.txt/' "$file"

    # 2. Añadir las dos nuevas líneas al final del archivo
    echo -e "\nmssfix 1450\nmute-replay-warnings" >> "$file"

    echo "Modificación completada para $file."
    echo "---"
done

echo "¡Script finalizado! Todos los archivos .ovpn han sido modificados."
