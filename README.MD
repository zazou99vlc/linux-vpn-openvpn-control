# Asistente de Conexión VPN (v4.5)

Un script en Python diseñado para gestionar conexiones OpenVPN de forma robusta, segura y desatendida. Ahora disponible en Español e Inglés.

Aunque la función de detección de puerto está optimizada para PrivateVPN, el resto del script funciona con cualquier proveedor que use archivos .ovpn.

## ¿Qué hace este script?

*   Conexión "Roca": Si la VPN se cae, intenta reconectar automáticamente.
*   Kill-Switch: Si no puede reconectar, corta internet para que tu IP real nunca quede expuesta.
*   Guardián de Rutas: NetworkManager suele tener "puertas traseras" (fugas de rutas) que exponen tu IP. Este script vigila y cierra esas fugas al instante, obligando al tráfico a ir por la VPN.
*   Modo "Ninja": No modifica tus archivos originales ni guarda contraseñas en texto plano. Todo se gestiona en memoria.
*   Detección de Puerto: (Solo PrivateVPN) Te dice qué puerto tienes abierto para configurar tu Torrent/P2P.

## Requisitos

Solo necesitas tener instaladas las herramientas básicas.

Sistema:
*   openvpn, curl, sudo
*   NetworkManager: (Generalmente preinstalado). El script lo necesita precisamente para corregir su comportamiento y evitar fugas de datos.

Python:
*   requests, ping3

> Instalación rápida en Arch/Manjaro:
> sudo pacman -S openvpn curl python-requests
> yay -S python-ping3

## Cómo usarlo (Instalación Limpia)

Olvídate de editar archivos o scripts extraños. Ahora es mucho más fácil:

1.  Copia tus archivos `.ovpn` en la misma carpeta que este script.
2.  Dale permisos de ejecución:
        chmod +x convpn44.py
    
3.  Ejecuta el script:
    Puedes hacer doble clic sobre él o lanzarlo desde la terminal:
        ./convpn44.py
    
4.  Configura tus datos:
    La primera vez que intentes conectar, el script te pedirá tu Usuario y Contraseña de la VPN.
    *   Se guardarán de forma protegida en un archivo local (config.json).
    *   Puedes cambiarlos cuando quieras desde el menú 'M'.

¡Y listo! El script se encarga de optimizar la conexión y mantenerla segura.

## Menú de Opciones

Al arrancar, verás tus ubicaciones disponibles. Además, puedes pulsar 'M' para acceder a:
*   Configurar Visualización: Elige cómo quieres que se vean los nombres de los archivos (ej: Solo Ciudad o País-Ciudad).
*   Cambiar Idioma: Español / English.
*   Gestionar Credenciales: Por si cambias de contraseña o usuario.

## Nota sobre Seguridad

Este script requiere permisos de administrador (sudo) para poder modificar las rutas de red y protegerte de fugas. Te pedirá la contraseña al iniciarse.
