#!/usr/bin/env python3
import os
import subprocess
import time
import sys
import threading
import re
from shutil import which

# --- BIBLIOTECAS ADICIONALES ---
try:
    import ping3
    ping3.EXCEPTIONS = True
    import requests
except ImportError as e:
    missing_lib = str(e).split("'")[1]
    print(f"\033[1;31mError: La biblioteca '{missing_lib}' no está instalada.\033[0m")
    print(f"\033[1;33mPor favor, ejecute: pip install {missing_lib}\033[0m")
    print("\033[1;33mEl script se cerrará en 10 segundos...\033[0m")
    time.sleep(10)
    sys.exit(1)

# --- COLORES Y CONSTANTES ---
BLUE = "\033[1;34m"
YELLOW = "\033[1;33m"
GREEN = "\033[1;32m"
RED = "\033[1;31m"
NC = "\033[0m"

LOG_FILE = "openvpn.log"
PORT_FILE = "forwarded_port.txt"
CONNECTION_TIMEOUT = 20
MONITOR_INTERVAL = 45
CONNECTION_ATTEMPTS = 3
IP_VERIFY_ATTEMPTS = 3
RETRY_DELAY = 10
CURL_TIMEOUT = 4
IP_RETRY_DELAY = 5
PING_TIMEOUT = 4
API_TIMEOUT = 5

# --- VARIABLES GLOBALES ---
ORIGINAL_DEFAULT_ROUTE = None
ORIGINAL_DEFAULT_DEV = None
ORIGINAL_DEFAULT_GW = None
ACTIVE_CONNECTION_NAME = None

# --- FUNCIONES DE UTILIDAD ---
def safe_print(message, dynamic=False):
    subprocess.run(["stty", "sane"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if dynamic:
        sys.stdout.write(f"\r\033[K{message}")
        sys.stdout.flush()
    else:
        sys.stdout.write(f"\r\033[K{message}\n")
        sys.stdout.flush()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def send_critical_notification(title, message):
    if which("notify-send"):
        subprocess.run(["notify-send", "--urgency=critical", "--icon=network-vpn", title, message])

def is_valid_ip(ip_string):
    if not ip_string: return False
    return re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip_string) is not None

def get_current_default_route():
    try:
        ip_route_output = subprocess.run(["ip", "route"], capture_output=True, text=True).stdout
        match = re.search(r"^default via (\S+) dev (\S+)", ip_route_output, re.MULTILINE)
        if match: return match.group(1), match.group(2)
    except Exception as e:
        safe_print(f"{RED}Error al obtener la ruta por defecto actual: {e}{NC}")
    return None, None

def get_vpn_internal_ip():
    try:
        ip_addr_output = subprocess.run(["ip", "addr"], capture_output=True, text=True, check=True).stdout
        match = re.search(r"inet\s+([\d\.]+)/[\d]+\s+scope\s+global\s+(tun\d+)", ip_addr_output)
        if match:
            return match.group(1)
    except Exception as e:
        safe_print(f"{RED}  > Error al buscar IP interna de la VPN: {e}{NC}")
    return None

def get_forwarded_port(internal_ip):
    if not internal_ip:
        return None
    
    api_url = f"https://connect.pvdatanet.com/v3/Api/port?ip[]={internal_ip}"
    for attempt in range(1, 4):
        try:
            safe_print(f"{YELLOW}Consultando puerto asignado (Intento {attempt}/3)...{NC}", dynamic=True)
            response = requests.get(api_url, timeout=API_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            
            if data.get("supported") is True and "status" in data:
                status_text = data["status"]
                port_match = re.search(r'\d+', status_text)
                if port_match:
                    port = port_match.group(0)
                    safe_print(f"{GREEN}Puerto asignado por la VPN: {port}{NC}")
                    return port
            else:
                safe_print(f"{YELLOW}El servidor no soporta reenvío de puertos o devolvió un error.{NC}")
                return "No Soportado"
        except requests.exceptions.RequestException:
            if attempt < 3:
                time.sleep(2)
            else:
                safe_print(f"{RED}No se pudo contactar con la API de puertos.{NC}")
        except Exception:
            safe_print(f"{RED}Respuesta inesperada de la API de puertos.{NC}")
    
    return "No Disponible"

def cleanup(is_failure=False):
    global ORIGINAL_DEFAULT_ROUTE, ORIGINAL_DEFAULT_DEV, ORIGINAL_DEFAULT_GW, ACTIVE_CONNECTION_NAME

    if ACTIVE_CONNECTION_NAME:
        try:
            safe_print(f"{BLUE}Devolviendo control de la ruta por defecto a '{ACTIVE_CONNECTION_NAME}'...{NC}")
            subprocess.run(["sudo", "nmcli", "connection", "modify", ACTIVE_CONNECTION_NAME, "ipv4.never-default", "no"], check=True, capture_output=True)
            subprocess.run(["sudo", "nmcli", "connection", "modify", ACTIVE_CONNECTION_NAME, "ipv4.ignore-auto-routes", "no"], check=True, capture_output=True)
            ACTIVE_CONNECTION_NAME = None
        except Exception as e:
            safe_print(f"{RED}Advertencia: No se pudo restaurar la configuración de NetworkManager: {e}{NC}")
    
    safe_print(f"\n{YELLOW}Iniciando secuencia de desconexión...{NC}")

    if is_failure:
        safe_print(f"{RED}¡FALLO CRÍTICO DETECTADO! Activando kill switch de red...{NC}")
        subprocess.run(["sudo", "nmcli", "networking", "off"], capture_output=True, text=True)
        send_critical_notification("FALLO CRÍTICO DE VPN", "Kill switch activado. Para reactivar: sudo nmcli networking on")

    safe_print(f"{BLUE}Terminando procesos de OpenVPN...{NC}")
    subprocess.run(["sudo", "killall", "-q", "openvpn"], capture_output=True)

    if ORIGINAL_DEFAULT_GW and ORIGINAL_DEFAULT_DEV and not is_failure:
        safe_print(f"{YELLOW}Intentando restaurar la ruta por defecto original...{NC}")
        ip_route_output = subprocess.run(["ip", "route"], capture_output=True, text=True).stdout
        if f"default via {ORIGINAL_DEFAULT_GW} dev {ORIGINAL_DEFAULT_DEV}" not in ip_route_output:
            try:
                subprocess.run(["sudo", "ip", "route", "del", "default", "dev", "tun0"], stderr=subprocess.DEVNULL, check=False)
                subprocess.run(["sudo", "ip", "route", "del", "default", "dev", "tun1"], stderr=subprocess.DEVNULL, check=False)
                safe_print(f"{YELLOW}  Añadiendo ruta original: {ORIGINAL_DEFAULT_GW} via {ORIGINAL_DEFAULT_DEV}.{NC}")
                subprocess.run(["sudo", "ip", "route", "add", "default", "via", ORIGINAL_DEFAULT_GW, "dev", ORIGINAL_DEFAULT_DEV], check=True)
                safe_print(f"{GREEN}Ruta por defecto restaurada.{NC}")
            except Exception as e:
                safe_print(f"{RED}Error al restaurar la ruta por defecto: {e}{NC}")
        else:
            safe_print(f"{GREEN}La ruta por defecto ya está en su estado original.{NC}")

    script_dir = os.path.dirname(os.path.realpath(__file__))
    log_file_path = os.path.join(script_dir, LOG_FILE)
    if os.path.exists(log_file_path): os.remove(log_file_path)
    
    port_file_path = os.path.join(script_dir, PORT_FILE)
    if os.path.exists(port_file_path):
        os.remove(port_file_path)
    
    safe_print(f"\n{GREEN}Limpieza completada.{NC}")
    if is_failure:
        safe_print(f"{YELLOW}IMPORTANTE: La red ha sido DESACTIVADA.{NC}")
        safe_print(f"Para reactivarla, ejecuta: {GREEN}sudo nmcli networking on{NC}")

def keep_sudo_alive():
    while True:
        subprocess.run(["sudo", "-v"], capture_output=True)
        time.sleep(60)

def check_and_set_default_route():
    safe_print(f"{BLUE}Verificando y estableciendo ruta por defecto a la VPN...{NC}")
    tun_interface = None
    try:
        interfaces_output = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True).stdout
        match = re.search(r'\d+:\s*(tun\d+):', interfaces_output)
        if match:
            tun_interface = match.group(1)
        else:
            safe_print(f"{RED}  Error: No se encontró una interfaz TUN activa.{NC}")
            return False
    except Exception as e:
        safe_print(f"{RED}  Error al buscar interfaz TUN: {e}{NC}")
        return False

    try:
        subprocess.run(["sudo", "ip", "route", "add", "default", "dev", tun_interface], check=True, stderr=subprocess.DEVNULL)
        safe_print(f"{GREEN}  Ruta por defecto establecida con éxito a {tun_interface}.{NC}")
    except subprocess.CalledProcessError:
        safe_print(f"{YELLOW}  La ruta por defecto a {tun_interface} ya parece existir. Continuando...{NC}")
    except Exception as e:
        safe_print(f"{RED}  Error al establecer la ruta por defecto: {e}{NC}")
        return False
    return True

def establish_connection(selected_file, selected_location, initial_ip, is_reconnecting=False):
    try:
        global ORIGINAL_DEFAULT_ROUTE, ORIGINAL_DEFAULT_DEV, ORIGINAL_DEFAULT_GW, ACTIVE_CONNECTION_NAME
        clear_screen()
        msg = "Se ha perdido la conexión. Intentando reconectar..." if is_reconnecting else f"Conectando a {selected_location}..."
        safe_print(f"{YELLOW}{msg}{NC}\n")

        script_dir = os.path.dirname(os.path.realpath(__file__))
        log_file_path = os.path.join(script_dir, LOG_FILE)

        if not is_reconnecting:
            ORIGINAL_DEFAULT_GW, ORIGINAL_DEFAULT_DEV = get_current_default_route()
            if ORIGINAL_DEFAULT_GW:
                ORIGINAL_DEFAULT_ROUTE = f"default via {ORIGINAL_DEFAULT_GW} dev {ORIGINAL_DEFAULT_DEV}"
                safe_print(f"{BLUE}Ruta por defecto original guardada: {ORIGINAL_DEFAULT_ROUTE}{NC}")
            else:
                safe_print(f"{RED}Error crítico: No se pudo determinar la ruta por defecto inicial.{NC}")
                return None, False, None

        for attempt in range(1, CONNECTION_ATTEMPTS + 1):
            safe_print(f"{BLUE}Iniciando conexión (Intento {attempt}/{CONNECTION_ATTEMPTS})...{NC}", dynamic=True)
            subprocess.run(["sudo", "killall", "-q", "openvpn"], capture_output=True)
            try:
                with open(log_file_path, "wb") as log:
                    config_path = os.path.join(script_dir, selected_file)
                    subprocess.Popen(["sudo", "openvpn", "--cd", script_dir, "--config", config_path], stdout=log, stderr=log)
            except Exception as e:
                safe_print(f"{RED}Error al iniciar OpenVPN: {e}{NC}")
                return None, False, None
            
            start_time, success = time.time(), False
            while time.time() - start_time < CONNECTION_TIMEOUT:
                if os.path.exists(log_file_path) and "Initialization Sequence Completed" in open(log_file_path, "r", errors='ignore').read():
                    success = True
                    break
                time.sleep(1)
                
            if success:
                safe_print(f"{GREEN}Proceso OpenVPN iniciado.{NC}")
                break
            
            safe_print(f"{RED}Intento {attempt} fallido.{NC}")
            if attempt < CONNECTION_ATTEMPTS: time.sleep(RETRY_DELAY)

        if not success:
            safe_print(f"{YELLOW}Fallo al iniciar OpenVPN. Mostrando resumen de error en 3 segundos...{NC}")
            time.sleep(3)
            display_failure_banner(f"No se pudo establecer la conexión tras {CONNECTION_ATTEMPTS} intentos.")
            cleanup(is_failure=is_reconnecting)
            return None, False, None

        safe_print(f"\n{BLUE}Estabilizando y verificando red...{NC}")
        time.sleep(3)
        
        safe_print(f"{YELLOW}Verificando conectividad básica (ping a 1.1.1.1)...{NC}", dynamic=True)
        try:
            ping3.ping("1.1.1.1", timeout=PING_TIMEOUT)
            safe_print(f"{GREEN}Verificando conectividad básica (ping a 1.1.1.1)... OK.{NC}")
        except Exception as e:
            safe_print(f"{YELLOW}Fallo de conectividad. Mostrando resumen de error en 3 segundos...{NC}")
            time.sleep(3)
            safe_print(f"{RED}Verificando conectividad básica (ping a 1.1.1.1)... FALLO.{NC}")
            display_failure_banner("Fallo de conectividad básica. El túnel no enruta tráfico.")
            cleanup(is_failure=is_reconnecting)
            return None, False, None

        new_ip, ip_verified, dns_fallback_used = "No se pudo obtener", False, False
        for attempt in range(1, IP_VERIFY_ATTEMPTS + 1):
            safe_print(f"{YELLOW}Verificando IP (Intento {attempt}/{IP_VERIFY_ATTEMPTS})...{NC}", dynamic=True)
            for service in ["ifconfig.me", "icanhazip.com", "ipinfo.io/ip"]:
                try:
                    res = subprocess.run(["curl", "-s", "--max-time", str(CURL_TIMEOUT), service], capture_output=True, text=True)
                    if res.returncode == 0 and is_valid_ip(res.stdout.strip()):
                        current_ip = res.stdout.strip()
                        if current_ip != initial_ip:
                            new_ip = current_ip
                            ip_verified = True
                            break
                except Exception:
                    pass
            if ip_verified:
                break
            if attempt < IP_VERIFY_ATTEMPTS:
                time.sleep(IP_RETRY_DELAY)

        if not ip_verified:
            safe_print(f"\n{YELLOW}La verificación de IP falló. Iniciando fallback de DNS...{NC}")
            resolv_path, resolv_backup_path = "/etc/resolv.conf", "/tmp/resolv.conf.convpn.bak"
            try:
                if os.path.exists(resolv_path):
                    subprocess.run(["sudo", "cp", resolv_path, resolv_backup_path], check=True)
                    cmd = f'echo "nameserver 1.1.1.1\n$(cat {resolv_backup_path})" | sudo tee {resolv_path}'
                    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL)
                    safe_print(f"{GREEN}DNS público añadido temporalmente. Reintentando...{NC}")
                    time.sleep(1)

                    for service in ["ifconfig.me", "icanhazip.com", "ipinfo.io/ip"]:
                        res = subprocess.run(["curl", "-s", "--max-time", str(CURL_TIMEOUT), service], capture_output=True, text=True)
                        if res.returncode == 0 and is_valid_ip(res.stdout.strip()) and res.stdout.strip() != initial_ip:
                            new_ip, ip_verified, dns_fallback_used = res.stdout.strip(), True, True
                            break
            except Exception as e: safe_print(f"{RED}Error durante el fallback de DNS: {e}{NC}")
            finally:
                if os.path.exists(resolv_backup_path):
                    try:
                        subprocess.run(["sudo", "mv", resolv_backup_path, resolv_path], check=True)
                        safe_print(f"{BLUE}Configuración de DNS original restaurada.{NC}")
                    except Exception: safe_print(f"{RED}¡Atención! No se pudo restaurar {resolv_path}.{NC}")

            if dns_fallback_used:
                safe_print(f"{GREEN}¡Éxito! Conexión establecida usando el DNS de fallback.{NC}")
            else:
                safe_print(f"{YELLOW}Fallo en la verificación de IP. Mostrando resumen de error en 3 segundos...{NC}")
                time.sleep(3)
                display_failure_banner("La IP no cambió (incluso con DNS de fallback).")
                cleanup(is_failure=is_reconnecting)
                return None, False, None

        safe_print(f"\n{BLUE}Conexión verificada. Obteniendo puerto reenviado...{NC}")
        internal_ip = get_vpn_internal_ip()
        forwarded_port = get_forwarded_port(internal_ip)

        if forwarded_port and forwarded_port.isdigit():
            try:
                port_file_path = os.path.join(script_dir, PORT_FILE)
                with open(port_file_path, 'w') as f:
                    f.write(str(forwarded_port))
                safe_print(f"{GREEN}Puerto {forwarded_port} guardado en '{PORT_FILE}'.{NC}")
            except Exception as e:
                safe_print(f"{RED}Advertencia: No se pudo guardar el puerto en el archivo: {e}{NC}")

        safe_print(f"\n{BLUE}Tomando control total de las rutas...{NC}")
        try:
            nmcli_output = subprocess.run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"], capture_output=True, text=True, check=True).stdout
            for line in nmcli_output.strip().split('\n'):
                parts = line.split(':')
                if len(parts) > 1 and parts[1].lower() != 'lo' and not parts[1].lower().startswith('tun'):
                    ACTIVE_CONNECTION_NAME = parts[0]
                    break
            
            if ACTIVE_CONNECTION_NAME:
                safe_print(f"  > Neutralizando la ruta por defecto de '{ACTIVE_CONNECTION_NAME}'...")
                subprocess.run(["sudo", "nmcli", "connection", "modify", ACTIVE_CONNECTION_NAME, "ipv4.never-default", "yes"], check=True, capture_output=True)
                subprocess.run(["sudo", "nmcli", "connection", "modify", ACTIVE_CONNECTION_NAME, "ipv4.ignore-auto-routes", "yes"], check=True, capture_output=True)
            else:
                safe_print(f"{YELLOW}  > Advertencia: No se pudo determinar la conexión principal para neutralizar.{NC}")

            if ORIGINAL_DEFAULT_GW and ORIGINAL_DEFAULT_DEV:
                safe_print(f"  > Eliminando la ruta por defecto original ({ORIGINAL_DEFAULT_GW})...")
                subprocess.run(["sudo", "ip", "route", "del", "default", "via", ORIGINAL_DEFAULT_GW, "dev", ORIGINAL_DEFAULT_DEV], check=False, capture_output=True)

        except Exception as e:
            safe_print(f"{RED}Error al tomar control de las rutas: {e}{NC}")
            safe_print(f"{YELLOW}La conexión podría ser inestable.{NC}")
        
        if not check_and_set_default_route():
            safe_print(f"{YELLOW}Fallo al establecer la ruta por defecto. Mostrando resumen de error en 3 segundos...{NC}")
            time.sleep(3)
            display_failure_banner("Fallo al establecer la ruta por defecto a la VPN.")
            cleanup(is_failure=True)
            return None, False, None

        return new_ip, dns_fallback_used, forwarded_port
    except KeyboardInterrupt:
        cleanup(is_failure=False)
        safe_print(f"\n{YELLOW}Conexión cancelada por el usuario.{NC}")
        return None, False, None

def check_connection_status(expected_ip):
    if subprocess.run(["pgrep", "-x", "openvpn"], capture_output=True).returncode != 0:
        safe_print(f"{RED}ESTADO: ¡DESCONECTADO! (Proceso OpenVPN no encontrado).{NC}")
        return True

    safe_print(f"{YELLOW}Verificando IP pública y ruta...{NC}", dynamic=True)
    try:
        interfaces_output = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True).stdout
        match = re.search(r'\d+:\s*(tun\d+):', interfaces_output)
        if match and f"default dev {match.group(1)}" in subprocess.run(["ip", "route"], capture_output=True, text=True).stdout:
            pass
        else:
            safe_print(f"{RED}ESTADO: ¡DESCONECTADO! (Ruta por defecto o interfaz TUN incorrecta).{NC}")
            return True
    except Exception as e:
        safe_print(f"{RED}ESTADO: ¡DESCONECTADO! (Error al verificar rutas: {e}).{NC}")
        return True

    current_ip = ""
    for _ in range(3):
        for service in ["ifconfig.me", "icanhazip.com", "ipinfo.io/ip"]:
            res = subprocess.run(["curl", "-s", "--max-time", str(CURL_TIMEOUT), service], capture_output=True, text=True)
            if res.returncode == 0 and is_valid_ip(res.stdout.strip()):
                current_ip = res.stdout.strip()
                if current_ip == expected_ip: return False
        time.sleep(IP_RETRY_DELAY)

    safe_print(f"{RED}ESTADO: ¡DESCONECTADO! (La IP pública es {current_ip or 'desconocida'}).{NC}")
    return True

def monitor_connection(selected_file, selected_location, initial_ip, vpn_ip, dns_fallback_used, forwarded_port):
    reconnection_count = 0
    route_correction_count = 0
    try:
        while True:
            clear_screen()
            safe_print(f"{BLUE}======================================={NC}")
            safe_print(f"{BLUE}  VPN EN FUNCIONAMIENTO (Modo Monitor){NC}")
            safe_print(f"{BLUE}======================================={NC}")
            safe_print(f"  Ubicación:         {YELLOW}{selected_location}{NC}")
            safe_print(f"  Reconexiones:      {RED}{reconnection_count}{NC}")
            safe_print(f"  Correcciones Ruta: {RED}{route_correction_count}{NC}")
            if dns_fallback_used: safe_print(f"  DNS Fallback:      {YELLOW}Activo (Servidor DNS con problemas){NC}")
            safe_print(f"  IP Esperada (VPN): {GREEN}{vpn_ip}{NC}")
            
            port_color = GREEN if forwarded_port and forwarded_port.isdigit() else YELLOW
            port_display = forwarded_port if forwarded_port else "Obteniendo..."
            safe_print(f"  Puerto Asignado:   {port_color}{port_display}{NC}")

            safe_print(f"  Comprobación:      {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            status_message = f"{GREEN}ESTADO: Conectado y verificado.{NC}"
            if ORIGINAL_DEFAULT_GW:
                try:
                    ip_route_output = subprocess.run(["ip", "route"], capture_output=True, text=True, check=True).stdout
                    if f"default via {ORIGINAL_DEFAULT_GW}" in ip_route_output:
                        subprocess.run(["sudo", "ip", "route", "del", "default", "via", ORIGINAL_DEFAULT_GW], check=False, capture_output=True)
                        route_correction_count += 1
                        status_message = f"{YELLOW}ESTADO: Ruta de DHCP corregida en este ciclo.{NC}"
                        time.sleep(1)
                except Exception as e:
                    safe_print(f"{RED}Error en guardián de rutas: {e}{NC}")

            if check_connection_status(expected_ip=vpn_ip):
                reconnection_count += 1
                safe_print(f"\n{YELLOW}Conexión perdida. Realizando limpieza antes de reconectar...{NC}")
                cleanup(is_failure=False)
                time.sleep(3)
                
                new_ip, new_dns_fallback, new_port = establish_connection(selected_file, selected_location, initial_ip, is_reconnecting=True)
                
                if not new_ip:
                    safe_print(f"\n{RED}La reconexión ha fallado. El kill switch ha sido activado.{NC}")
                    time.sleep(5)
                    return
                
                vpn_ip, dns_fallback_used, forwarded_port = new_ip, new_dns_fallback, new_port

                title = "VPN Reconectada: ¡Acción Requerida!"
                message = f"El puerto ha cambiado a {forwarded_port}.\nDebes reiniciar tus aplicaciones (aMule, Transmission) para usar la nueva configuración."
                send_critical_notification(title, message)

                display_success_banner(selected_location, initial_ip, vpn_ip, True, reconnection_count)
                safe_print(f"{GREEN}Reconexión exitosa. Reanudando monitorización...{NC}")
                time.sleep(4)
                continue

            safe_print(status_message)
            mins, secs = divmod(MONITOR_INTERVAL, 60)
            t_str = f"{mins} min" if mins > 0 else f"{secs} seg"
            safe_print(f"\n{YELLOW}Próxima comprobación en {t_str}. Presiona Ctrl+C para salir.{NC}")
            time.sleep(MONITOR_INTERVAL)
    except KeyboardInterrupt:
        cleanup(is_failure=False)
        safe_print(f"\n{YELLOW}Script finalizado por el usuario. La ventana se cerrará en 5 segundos...{NC}")
        time.sleep(5)

def display_failure_banner(reason):
    clear_screen()
    safe_print(f"{RED}======================================={NC}")
    safe_print(f"{RED}          ❌ FALLO DE CONEXIÓN")
    safe_print(f"{RED}======================================={NC}")
    safe_print(f"\n  {reason}")

def display_success_banner(location, initial_ip, new_ip, is_reconnecting=False, count=0):
    clear_screen()
    safe_print(f"{GREEN}======================================={NC}")
    safe_print(f"{GREEN}       ✔ CONEXIÓN ESTABLECIDA")
    safe_print(f"{GREEN}======================================={NC}")
    safe_print(f"  Ubicación:     {YELLOW}{location}{NC}")
    if is_reconnecting: safe_print(f"  Reconexiones:  {YELLOW}{count}{NC}")
    safe_print(f"  IP Original:   {YELLOW}{initial_ip}{NC}")
    safe_print(f"  IP VPN:        {GREEN}{new_ip}{NC}\n")

def get_user_choice(locations, last_choice=None):
    safe_print(f"{BLUE}--- UBICACIONES DISPONIBLES ---{NC}")
    for i, location in enumerate(locations, 1): safe_print(f"  {i}) {location}")
    safe_print("")

    prompt = f"Elige (1-{len(locations)}): "
    if last_choice: prompt = f"Elige (1-{len(locations)}) o Intro para reintentar '{locations[last_choice-1]}': "
    while True:
        try:
            choice_str = input(prompt)
            if not choice_str and last_choice: return last_choice
            choice = int(choice_str)
            if 1 <= choice <= len(locations): return choice
            safe_print(f"{RED}Selección fuera de rango.{NC}")
        except ValueError: safe_print(f"{RED}Por favor, introduce un número válido.{NC}")
        except KeyboardInterrupt:
            cleanup(is_failure=False)
            safe_print(f"\n{YELLOW}Operación cancelada. Saliendo en 5 segundos...{NC}")
            time.sleep(5)
            sys.exit(0)

def main():
    if not all(which(cmd) for cmd in ["openvpn", "curl", "sudo", "stty", "nmcli", "ip"]):
        safe_print(f"{RED}Error: Faltan dependencias (openvpn, curl, sudo, stty, nmcli, ip).{NC}")
        sys.exit(1)

    script_dir = os.path.dirname(os.path.realpath(__file__))
    
    clear_screen()
    safe_print(f"{YELLOW}Se solicitará la contraseña de administrador.{NC}")
    if subprocess.run(["sudo", "-v"], capture_output=True).returncode != 0:
        safe_print(f"{RED}Error: No se pudo obtener privilegios de sudo.{NC}")
        sys.exit(1)
    
    threading.Thread(target=keep_sudo_alive, daemon=True).start()

    safe_print(f"{BLUE}Verificando conectividad a Internet...{NC}")
    
    try:
        ping3.ping("1.1.1.1", timeout=2)
        safe_print(f"{GREEN}Conectividad a Internet confirmada.{NC}")
    except Exception:
        safe_print(f"{YELLOW}No se detecta conexión. Intentando reparación automática...{NC}")
        safe_print(f"{YELLOW}(Esto puede ocurrir si el script se cerró de forma incorrecta anteriormente){NC}")
        
        try:
            safe_print("  > Restaurando configuraciones de NetworkManager...")
            nmcli_output = subprocess.run(
                ["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"],
                capture_output=True, text=True
            ).stdout
            
            restored_connections = 0
            for line in nmcli_output.strip().split('\n'):
                parts = line.split(':')
                if len(parts) > 1 and parts[1].lower() != 'lo' and not parts[1].lower().startswith('tun'):
                    conn_name = parts[0]
                    subprocess.run(["sudo", "nmcli", "connection", "modify", conn_name, "ipv4.never-default", "no"], check=True, capture_output=True)
                    subprocess.run(["sudo", "nmcli", "connection", "modify", conn_name, "ipv4.ignore-auto-routes", "no"], check=True, capture_output=True)
                    restored_connections += 1
            if restored_connections == 0:
                safe_print(f"{YELLOW}  > No se encontraron conexiones activas que restaurar, procediendo a reiniciar la red.{NC}")

            safe_print("  > Reiniciando la pila de red (off/on)...")
            subprocess.run(["sudo", "nmcli", "networking", "off"], check=True, capture_output=True)
            time.sleep(10)
            subprocess.run(["sudo", "nmcli", "networking", "on"], check=True, capture_output=True)
            time.sleep(15)

            safe_print("  > Verificando la conectividad después de la reparación...")
            ping3.ping("1.1.1.1", timeout=3)
            safe_print(f"{GREEN}¡Éxito! La conexión a Internet ha sido restaurada.{NC}")
            time.sleep(4)
        except Exception as e:
            safe_print(f"\r\033[K{RED}Error Crítico: La reparación automática falló.{NC}")
            safe_print(f"{YELLOW}El problema parece ser externo al script (ej. Wi-Fi desconectado, sin señal, fallo del ISP).{NC}")
            safe_print(f"Por favor, asegúrate de tener una conexión a Internet funcional antes de volver a ejecutar el script.")
            safe_print(f"Error detallado: {e}")
            safe_print(f"\n{YELLOW}El script se cerrará en 15 segundos...{NC}")
            time.sleep(15)
            sys.exit(1)

    safe_print(f"\n{BLUE}Obteniendo IP pública actual...{NC}")
    res = subprocess.run(["curl", "-s", "--max-time", str(CURL_TIMEOUT), "ifconfig.me"], capture_output=True, text=True)
    initial_ip = res.stdout.strip()
    
    if not is_valid_ip(initial_ip):
        safe_print(f"{RED}Error crítico: No se pudo obtener una IP pública inicial válida.{NC}")
        safe_print(f"{YELLOW}Iniciando limpieza antes de salir...{NC}")
        safe_print(f"{BLUE}Si vienes de un cierre abrupto del script restaurará la conexión de red {NC}")
        cleanup(is_failure=False)
        safe_print(f"\n{YELLOW}El script se cerrará en 5 segundos...{NC}")
        time.sleep(5)
        sys.exit(1)
    try:
        ovpn_files = sorted([f for f in os.listdir(script_dir) if f.endswith(".ovpn")])
        if not ovpn_files: raise FileNotFoundError("No se encontraron archivos .ovpn")
        locations = [f.replace('.ovpn', '').split('-')[2] if len(f.split('-')) > 2 else f.replace('.ovpn', '') for f in ovpn_files]
    except Exception as e:
        safe_print(f"{RED}Error al procesar los archivos .ovpn en '{script_dir}': {e}{NC}")
        sys.exit(1)

    if not os.path.exists(os.path.join(script_dir, "pass.txt")):
        safe_print(f"{RED}Error: No se encuentra el archivo 'pass.txt' en '{script_dir}'.{NC}")
        sys.exit(1)

    last_choice = None
    while True:
        clear_screen()
        safe_print(f"{BLUE}======================================={NC}")
        safe_print(f"{BLUE}    Asistente de Conexión VPN")
        safe_print(f"{BLUE}======================================={NC}")
        safe_print(f"\nDirectorio: {script_dir}\nIP Original: {YELLOW}{initial_ip}{NC}\n")

        choice = get_user_choice(locations, last_choice)
        last_choice = choice
        selected_file, selected_location = ovpn_files[choice - 1], locations[choice - 1]

        new_ip, dns_fallback_used, forwarded_port = establish_connection(selected_file, selected_location, initial_ip)
        
        if new_ip:
            safe_print(f"{GREEN}Conexión verificada. Mostrando resumen en 10 segundos...{NC}")
            time.sleep(10)

            display_success_banner(selected_location, initial_ip, new_ip)
            time.sleep(4)
            monitor_connection(selected_file, selected_location, initial_ip, new_ip, dns_fallback_used, forwarded_port)
        else:
            safe_print(f"\n{YELLOW}Volviendo al menú en 5 segundos...{NC}")
            time.sleep(5)

if __name__ == "__main__":
    if "--run-in-terminal" not in sys.argv:
        script_path = os.path.realpath(__file__)
        # --- LÍNEA MODIFICADA ---
        terminals = {"gnome-terminal": "--", "konsole": "-e", "xfce4-terminal": "--hold -e", "xterm": "-e"}
        for term, args in terminals.items():
            if which(term):
                try:
                    # Para xfce4-terminal, el comando debe ser un solo argumento
                    if term == "xfce4-terminal":
                         command = f"{term} {args} \"python3 '{script_path}' --run-in-terminal\""
                    else:
                         command = f"{term} {args} python3 '{script_path}' --run-in-terminal"
                    
                    subprocess.run(command, shell=True, check=True)
                    sys.exit(0)
                except Exception as e:
                    safe_print(f"{RED}Error al lanzar {term}: {e}{NC}")
        safe_print(f"{RED}No se detectó un terminal compatible.{NC}")
        safe_print(f"{YELLOW}Ejecuta: {GREEN}python3 '{script_path}' --run-in-terminal{NC}")
        sys.exit(1)
    else:
        try:
            main()
        except KeyboardInterrupt:
            cleanup(is_failure=False)
            safe_print(f"\n{YELLOW}Script finalizado. Saliendo en 5 segundos...{NC}")
            time.sleep(5)
        except Exception as e:
            cleanup(is_failure=True)
            safe_print(f"\n{RED}Error inesperado: {e}{NC}")
            time.sleep(5)
            sys.exit(1)
