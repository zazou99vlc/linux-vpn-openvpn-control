Asistente VPN, para archivos ovpn como alternativa mas fiable que network manager por si solo

Un script para gestionar una conexión OpenVPN. Se encarga de conectar, monitorizar la estabilidad y reconectar si se cae, activando un kill-switch para evitar fugas de datos.

Características Principales

Conexión y Reconexión Automática: Si la conexión VPN se pierde, el script la restablece automáticamente.

Monitor y Kill-Switch: Si la VPN falla y no se puede reconectar, el script desactiva la red del sistema para prevenir que tu IP real quede expuesta.

Guardián de Rutas Anti-Fugas: Creado para combatir los fallos de desobediencia de Network Manager, que a veces intenta restaurar la ruta a internet original. El script lo previene de dos modos: primero, modifica la configuración de la conexión de red para que ignore las rutas automáticas. Además, un "Guardián" vigila cada segundo para detectar y eliminar al instante cualquier "puerta trasera" que pueda aparecer. El modo monitor analiza la frecuencia de estas correcciones para diagnosticar problemas de estabilidad (ej: DHCP del router).

Obtención de Puerto (Específico de Proveedor): Consulta la API del proveedor para obtener el puerto reenviado. Nota: Actualmente está implementado para PrivateVPN. Para otro proveedor, se necesita adaptar la función get_forwarded_port.

Menú Adaptativo: La lista de servidores se muestra en columnas y se ajusta al tamaño de la ventana de la terminal.

Requisitos

Software que necesitas tener instalado:
openvpn, curl, nmcli, notify-send
Librerías de Python: requests, ping3.

Para instalar las librerías:
pip install requests ping3.
En algunas distros como arch/manjaro para añadirlo hay que usar por ejemplo yay -S python-ping3 asi el se encarga de las dependencias

Configuración

Pon los archivos .ovpn en la misma carpeta que el script.

Crea un archivo llamado pass.txt. Dentro, pon tu usuario en la primera línea y tu contraseña en la segunda.

Importante: Protege tus credenciales. El script te avisará si los permisos son inseguros.
chmod 600 pass.txt

Uso

El script necesita privilegios de sudo para gestionar las rutas de red, por lo que pedirá la contraseña al inicio.

Ejecución

Desde terminal: python3 el_nombre_del_script.py
dándole permisos de ejecución basta hacer doble click y ejecutarlo el se encarga de abrirse en un terminal

Script de Ayuda

modificar_ovpn.sh: En el repositorio hay un script de shell para preparar en masa los archivos .ovpn (por ejemplo, para añadirles la directiva auth-user-pass pass.txt) y unas directivas para que el log de la vpn este limpio.


