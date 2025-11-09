Asistente de Conexión VPN (openVPN) para Linux. Probado para PrivateVPN.

Un conjunto de scripts avanzados para gestionar conexiones OpenVPN en Linux de forma segura, evitando las "fugas" de datos de NetworkManager (amordazándolo sin prescindir de él).
¿Qué es esto?

Es una solución completa para cualquiera que use una VPN en un escritorio Linux y se tome la seguridad en serio. El script principal, convpn.py, no es solo un conector. Es un guardián que toma el control total de tu red para asegurar que ni un solo paquete se escape sin encriptar, incluso si la conexión falla.

Los otros scripts son lanzadores para que, con un doble clic, puedas configurar y abrir tus aplicaciones de descarga (Transmission, aMule) con el puerto correcto que te asigna la VPN, sin tocar el teclado.
El Problema: La Puerta Trasera de NetworkManager

Si usas el gestor de conexiones de Linux (NetworkManager) para tu VPN, probablemente no estás tan seguro como crees.

Cuando te conectas a la VPN, NetworkManager es "demasiado servicial". En lugar de cerrar tu conexión a internet normal, simplemente le baja la prioridad. Esto crea una ruta por defecto redundante. Si tu conexión VPN falla por un solo segundo, el sistema puede decidir que la ruta original es la mejor opción y empezar a enviar tu tráfico por ella, sin encriptar.

Este script soluciona eso de forma radical: toma el control de la tabla de rutas, elimina la ruta original y se asegura de que la única salida posible sea a través del túnel de la VPN.
Características Principales

    Kill Switch Real y Autoreparación: Si la conexión falla, desactiva toda la red a nivel de sistema operativo para garantizar que no haya fugas.
    Tranquilidad garantizada: Si el kill switch te deja sin internet, o si el script se cierra de forma incorrecta (por un reinicio, un cuelgue, etc.), no tienes que hacer nada manual. Simplemente vuelve a ejecutar convpn.py y el script detectará el problema y restaurará tu conexión a internet antes de mostrarte el menú.

    Control Total de Rutas: Elimina la ruta por defecto original para evitar fugas de datos.

    Monitorización Constante: Comprueba la conexión cada minuto y reconecta automáticamente si se pierde.

    Obtención de Puerto Automática (PrivateVPN): Detecta y muestra el puerto reenviado por la VPN, específico para usuarios de PrivateVPN.

    Lanzadores de Aplicaciones (Transmission-GTK / aMule): Scripts "doble-clic" para configurar y lanzar tus aplicaciones de descarga con el puerto correcto.

    Sin "Demonios Malos": La filosofía es simple. Los scripts configuran tus aplicaciones modificando sus archivos de configuración, sin depender de servicios en segundo plano, puertos RPC ni autenticaciones complejas.

Compatibilidad

Este conjunto de scripts ha sido diseñado y probado con PrivateVPN. La lógica para la obtención automática del puerto reenviado depende específicamente de la API de este proveedor.

    ✅ PrivateVPN: Totalmente compatible. La obtención del puerto reenviado funcionará automáticamente.

    🟡 Otros Proveedores con Reenvío de Puertos: Parcialmente compatible.

        El script principal convpn.py gestionará la conexión y el kill switch perfectamente.

        La obtención automática del puerto fallará. Para que funcione, necesitarías adaptar la función get_forwarded_port() en convpn.py para que use la API de tu proveedor.

    ❌ Proveedores sin Reenvío de Puertos: Parcialmente compatible.

        El script convpn.py funcionará perfectamente para establecer una conexión segura. Simplemente ignora la funcionalidad del puerto.

Instalación y Requisitos

Necesitas tener algunas cosas instaladas en tu sistema.

1. Herramientas de Terminal:
Asegúrate de tener openvpn, curl, jq y network-manager.

# Ejemplo para Arch/Manjaro
sudo pacman -S openvpn curl jq network-manager

2. Bibliotecas de Python:
Necesitas requests y ping3. Es posible que requests ya esté instalado en tu sistema.

¡OJO CON PING3! Muchas distribuciones de Linux protegen los directorios del sistema de Python, por lo que pip3 install ping3 puede fallar o requerir permisos especiales. La forma más segura y recomendada es instalarlo desde el gestor de paquetes de tu distribución.
code Code

# Ejemplo para Arch/Manjaro
yay -S python-ping3

# Para otras distros, busca "python ping3" en tu gestor de software.

Configuración (Pasos Previos)

Antes de usar los scripts, necesitas preparar tus archivos.

Paso 1: Preparar la Carpeta

    Crea una carpeta donde quieras guardar todo.

    Pon todos los scripts (convpn.py, iniciar_amule_lanzador.sh, iniciar_transmission_lanzador.sh, modificar_ovpn.sh) en esta carpeta.

    Recomendación: Guarda tus archivos .ovpn originales en una carpeta segura. Luego, copia los que quieras usar en la carpeta de los scripts para que sean modificados.

Paso 2: Modificar los Archivos .ovpn
Tus archivos .ovpn necesitan ser modificados para que funcionen con el script. Para hacerlo de forma automática:

    Abre una terminal en la carpeta que has creado.

    Dale permisos de ejecución al script modificador: chmod +x modificar_ovpn.sh

    Ejecútalo: ./modificar_ovpn.sh

Este script hará dos cosas en todos tus archivos .ovpn:

    Les dirá que lean el usuario y la contraseña del archivo pass.txt.

    Añadirá dos líneas para evitar errores de paquetes (MTU) y mantener el log de conexión limpio.

Paso 3: Crear el Archivo de Contraseña

    Crea un archivo de texto llamado pass.txt en la misma carpeta.

    Dentro, pon tu nombre de usuario de la VPN en la primera línea y tu contraseña en la segunda.

    Importante: Asegura este archivo. Abre una terminal en la carpeta y ejecuta:

    chmod 600 pass.txt

    Esto asegura que solo tú puedas leer el archivo.

¿Cómo se Usa?

La idea es que no tengas que usar el teclado.

    Para Conectar la VPN: Haz doble clic en convpn.py. Se abrirá una terminal, te pedirá la contraseña de sudo y te mostrará el menú para elegir una ubicación. Una vez conectado, entrará en modo monitor.

    Para Lanzar aMule/Transmission: Mientras la VPN está conectada, haz doble clic en iniciar_amule_lanzador.sh o iniciar_transmission_lanzador.sh. Se abrirá otra terminal, configurará el puerto automáticamente y lanzará la aplicación.

¿Qué Modifica este Script en tu Sistema?

Para tu tranquilidad, este conjunto de scripts está diseñado para ser lo menos invasivo posible.

    Archivos que modifica:

        Los archivos de configuración de puertos de aMule y Transmission-GTK en tu carpeta de usuario (~/.aMule/amule.conf y ~/.config/transmission/settings.json).

        Tus archivos .ovpn (solo si ejecutas modificar_ovpn.sh).

    Configuración del sistema que modifica (temporalmente):

        La configuración de rutas de NetworkManager y la tabla de enrutamiento del sistema. Esto es 100% reversible. Al salir del script con Ctrl+C o al volver a iniciarlo después de un cierre incorrecto, la configuración de NetworkManager se restaura a su estado original.

El script no instala nada de forma permanente ni modifica archivos críticos del sistema.
Aviso Legal

Este es un proyecto personal creado por curiosidad. Funciona para mí, pero úsalo bajo tu propia responsabilidad. No me hago responsable de posibles problemas. Revisa el código para entender lo que hace antes de ejecutarlo.
FIN DEL ARCHIVO README.md
  
