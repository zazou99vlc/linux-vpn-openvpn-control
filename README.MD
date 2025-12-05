Asistente de Conexión VPN (v97)

Un script en Python diseñado para gestionar conexiones OpenVPN de forma robusta, segura y totalmente desatendida. Disponible en Español e Inglés.

Este asistente automatiza todo el proceso de conexión, vigilancia y reparación de la red, ideal para mantener tu privacidad sin tener que vigilar la ventana de comandos. Aunque la detección de puerto está optimizada para la API de PrivateVPN, el resto de funcionalidades (conexión, kill-switch, DNS leak protection) funciona con cualquier proveedor que use archivos .ovpn.
¿Qué hace este script?
🛡️ Seguridad y Privacidad

    Kill-Switch Inteligente: Si la VPN se cae y no puede reconectar, corta el tráfico de red inmediatamente para evitar exponer tu IP real.

    Blindaje IPv6: Bloquea totalmente el tráfico IPv6 (vía Firewall y NetworkManager) para evitar fugas de identidad, ya que muchas VPNs solo protegen IPv4.

    Guardián de Rutas (Route Guardian): NetworkManager a veces intenta "escapar" de la VPN creando rutas por defecto inseguras. Este script vigila la tabla de enrutamiento cada segundo y elimina cualquier fuga al instante.

    Gestión de DNS Anti-Leak: Configura automáticamente las DNS para evitar fugas, soportando tanto systemd-resolved (Arch Linux/Manjaro) como la gestión estándar de NetworkManager.

⚙️ Automatización y Estabilidad

    Conexión "Roca": Si la conexión se pierde, el script lo detecta, limpia el entorno y reconecta automáticamente.

    Script Post-Conexión: Puedes configurar un script externo (opcional) que se ejecutará automáticamente cada vez que la VPN conecte o reconecte (ideal para actualizar puertos en Transmission/aMule).

    Análisis de Estabilidad: El script analiza si las desconexiones siguen un patrón (ej. renovación DHCP del router) y te avisa.

    Cifrado por Hardware: Tus credenciales se guardan cifradas vinculadas al ID físico de tu máquina. Si copian tu archivo de configuración a otro PC, no funcionará.

🔌 Utilidades

    Detección de Puerto: (Solo PrivateVPN) Consulta la API para decirte qué puerto tienes abierto para P2P.

    Formateo de Nombres: Limpia los nombres de los archivos .ovpn para mostrarlos bonitos (ej: "[ES] Madrid" en lugar de "privatevpn-madrid-tun-443.ovpn").

Requisitos e Instalación

El script está diseñado para ser ligero. Solo necesitas el script de Python y tus archivos .ovpn.

1. Dependencias del Sistema:
Necesitas herramientas básicas de red.

    openvpn, curl, sudo, iptables, nmcli (NetworkManager).

2. Librerías de Python:
El script usa requests y ping3.

    IMPORTANTE: Para ping3, se recomienda usar el gestor de paquetes de tu distribución en lugar de pip, para evitar conflictos de permisos con sudo.

    Arch Linux / Manjaro:
    code Bash

    
sudo pacman -S openvpn curl python-requests
yay -S python-ping3

  

Debian / Ubuntu / Mint:
code Bash

    
sudo apt install openvpn curl python3-requests python3-ping3

  

Fedora:
code Bash

        
    sudo dnf install openvpn curl python3-requests python3-ping3

      

Cómo usarlo
1. Preparación

Crea una carpeta y mete dentro:

    El script convpn97.py.

    Tus archivos .ovpn (tantos como quieras).

    (Opcional) Tu script .sh para actualizar puertos si lo usas.

2. Ejecución

No necesitas abrir una terminal manualmente si no quieres. El script es capaz de detectar si se está ejecutando en segundo plano y abrirá su propia ventana de terminal automáticamente.

Puedes ejecutarlo de varias formas:

    Opción A (Recomendada): Ejecuta python3 convpn97.py

    Opción B: Dale permisos de ejecución (chmod +x convpn97.py) y haz doble clic sobre él o ejecútalo como ./convpn97.py.

Al iniciar por primera vez, el asistente te guiará:

    Idioma: Selecciona Español o Inglés.

    Credenciales: Te pedirá tu usuario y contraseña de la VPN. Se guardarán cifrados localmente.

    Formato de Nombres: Te preguntará cómo quieres ver la lista de servidores (ej. Si prefieres ver "País - Ciudad" o solo "Ciudad").

3. Menú de Configuración (Tecla 'M')

En la pantalla de selección de servidor, puedes pulsar 'M' para:

    Configurar Script Post-Conexión: Vincula un script (bash/python) para que se ejecute tras conectar. Útil para actualizar clientes Torrent con el nuevo puerto.

    Crear/Actualizar Lanzador: Crea un acceso directo en tu menú de aplicaciones.

        Nota: Si descargas una nueva versión del script, usa esta opción de nuevo. El script detectará los lanzadores antiguos, los borrará y creará uno nuevo apuntando a la versión correcta.

    Gestionar Credenciales: Por si cambias tu contraseña.

    Cambiar Idioma y Visualización.

Funcionamiento Detallado

    Inicio: El script verifica tu conexión actual y tu IP real.

    Conexión: Modifica temporalmente el perfil de red para evitar conflictos, lanza OpenVPN y espera a que se estabilice.

    Verificación:

        Hace ping (usando ping3) para verificar conectividad.

        Comprueba que tu IP pública haya cambiado.

        Verifica que la ruta por defecto apunte a la VPN.

    Monitorización:

        Entra en un bucle donde vigila la conexión constantemente.

        Si detecta una caída o una fuga de ruta, activa el protocolo de reconexión.

        Si reconecta con éxito, vuelve a lanzar tu script post-conexión (si lo tienes configurado).

Nota: Este script requiere privilegios de sudo para modificar rutas y firewall. Te pedirá la contraseña al inicio y la mantendrá activa mientras el script funcione.
