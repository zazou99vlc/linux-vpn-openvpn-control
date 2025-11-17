#!/usr/bin/env python3
import os
import subprocess
import time
import sys
import threading
import re
from shutil import which
from datetime import datetime

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
LAST_CHOICE_FILE = "last_choice.txt"
CONNECTION_TIMEOUT = 20
MONITOR_INTERVAL = 45
ROUTE_GUARDIAN_INTERVAL = 1
CONNECTION_ATTEMPTS = 3
IP_VERIFY_ATTEMPTS = 3
RETRY_DELAY = 10
CURL_TIMEOUT = 4
IP_RETRY_DELAY = 5
PING_TIMEOUT = 4
API_TIMEOUT = 5

# --- VARIABLES GLOBALES ---
ORIGINAL_DEFAULT_ROUTE_DETAILS = None
ROUTE_CORRECTION_COUNT = 0
ORIGINAL_RESOLV_CONF_BACKUP = "/tmp/resolv.conf.original.bak"
CONNECTION_MODIFIED = False
GUARDIAN_STOP_EVENT = threading.Event()
RECONNECTION_LOG_FILE = "reconnections.log"
CONNECTION_START_TIME = None
LAST_RECONNECTION_TIME = None

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

def get_current_default_route_details():
    try:
        ip_route_output = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True).stdout
        match = re.search(r"^default (.*)", ip_route_output, re.MULTILINE)
        if match:
            return match.group(1).strip()
    except Exception as e:
        safe_print(f"{RED}Error al obtener la ruta por defecto actual: {e}{NC}")
    return None

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
    global ORIGINAL_DEFAULT_ROUTE_DETAILS, ORIGINAL_RESOLV_CONF_BACKUP, CONNECTION_MODIFIED
    safe_print(f"\n{YELLOW}Iniciando secuencia de limpieza...{NC}")

    if CONNECTION_MODIFIED:
        safe_print(f"{BLUE}Realizando restauración de red completa...{NC}")
        
        subprocess.run(["sudo", "killall", "-q", "openvpn"], capture_output=True)
        time.sleep(1)

        if os.path.exists(ORIGINAL_RESOLV_CONF_BACKUP):
            safe_print(f"  > Restaurando configuración de DNS original...")
            try:
                subprocess.run(["sudo", "mv", ORIGINAL_RESOLV_CONF_BACKUP, "/etc/resolv.conf"], check=True)
            except Exception as e:
                safe_print(f"{RED}    ¡ATENCIÓN! No se pudo restaurar /etc/resolv.conf: {e}{NC}")

        discovered_active_connection = None
        try:
            nmcli_output = subprocess.run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"], capture_output=True, text=True, check=True).stdout
            for line in nmcli_output.strip().split('\n'):
                parts = line.split(':')
                if len(parts) > 1 and parts[1].lower() not in ['lo'] and not parts[1].lower().startswith('tun'):
                    discovered_active_connection = parts[0]
                    break
        except Exception:
            pass

        if discovered_active_connection:
            safe_print(f"{BLUE}  > Usando NetworkManager para restaurar la conexión '{discovered_active_connection}'...{NC}")
            try:
                safe_print(f"    - Paso 1: Restaurando permisos del perfil...")
                subprocess.run(["sudo", "nmcli", "connection", "modify", discovered_active_connection, "ipv4.never-default", "no"], check=True, capture_output=True)
                subprocess.run(["sudo", "nmcli", "connection", "modify", discovered_active_connection, "ipv4.ignore-auto-routes", "no"], check=True, capture_output=True)
                
                safe_print(f"    - Paso 2: Pidiendo a NetworkManager que reactive la conexión...")
                subprocess.run(["sudo", "nmcli", "connection", "up", discovered_active_connection], check=True, capture_output=True)
                
                safe_print(f"{BLUE}    - Paso 3: Esperando 5 segundos a que la red se estabilice...{NC}")
                time.sleep(5)
                final_route = get_current_default_route_details()
                if final_route:
                    safe_print(f"{GREEN}    ¡Éxito! NetworkManager ha restaurado la conexión y la ruta por defecto.{NC}")
                    safe_print(f"{GREEN}      Ruta actual: default {final_route}{NC}")
                else:
                    safe_print(f"{RED}    ¡ATENCIÓN! La reactivación de la conexión no estableció una ruta por defecto. Revise su red.{NC}")
            except Exception as e:
                safe_print(f"{RED}    Error crítico al intentar restaurar la conexión con NetworkManager: {e}{NC}")
                safe_print(f"{YELLOW}    Puede que necesites reiniciar la red manualmente: sudo nmcli networking off && sudo nmcli networking on{NC}")
        else:
            safe_print(f"{YELLOW}  > No se encontró una conexión de red principal activa para restaurar automáticamente.{NC}")

    if is_failure:
        safe_print(f"{RED}¡FALLO CRÍTICO DETECTADO! Activando kill switch de red...{NC}")
        subprocess.run(["sudo", "nmcli", "networking", "off"], capture_output=True, text=True)
        send_critical_notification("FALLO CRÍTICO DE VPN", "Kill switch activado. Para reactivar: sudo nmcli networking on")

    script_dir = os.path.dirname(os.path.realpath(__file__))
    log_file_path = os.path.join(script_dir, LOG_FILE)
    if os.path.exists(log_file_path): os.remove(log_file_path)
    
    port_file_path = os.path.join(script_dir, PORT_FILE)
    if os.path.exists(port_file_path):
        os.remove(port_file_path)
    
    reconnection_log_path = os.path.join(script_dir, RECONNECTION_LOG_FILE)
    if os.path.exists(reconnection_log_path):
        os.remove(reconnection_log_path)
    
    CONNECTION_MODIFIED = False
    
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
    global ORIGINAL_DEFAULT_ROUTE_DETAILS, CONNECTION_MODIFIED, CONNECTION_START_TIME
    try:
        CONNECTION_START_TIME = time.time()

        try:
            start_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(CONNECTION_START_TIME))
            script_dir = os.path.dirname(os.path.realpath(__file__))
            log_path = os.path.join(script_dir, RECONNECTION_LOG_FILE)
            with open(log_path, 'w') as f:
                f.write(f"Hora de conexión: {start_time_str}\n")
        except Exception as e:
            safe_print(f"{RED}Error al crear el log de sesión: {e}{NC}")

        clear_screen()
        msg = "Se ha perdido la conexión. Intentando reconectar..." if is_reconnecting else f"Conectando a {selected_location}..."
        safe_print(f"{YELLOW}{msg}{NC}\n")

        script_dir = os.path.dirname(os.path.realpath(__file__))
        log_file_path = os.path.join(script_dir, LOG_FILE)

        if not is_reconnecting:
            ORIGINAL_DEFAULT_ROUTE_DETAILS = get_current_default_route_details()
            if ORIGINAL_DEFAULT_ROUTE_DETAILS:
                safe_print(f"{BLUE}Ruta por defecto original detectada: default {ORIGINAL_DEFAULT_ROUTE_DETAILS}{NC}")
            else:
                safe_print(f"{RED}Error crítico: No se pudo determinar la ruta por defecto inicial.{NC}")
                return None, False, None

        safe_print(f"\n{BLUE}Preparando la conexión de red principal para la VPN...{NC}")
        try:
            active_connection_name = None
            nmcli_output = subprocess.run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"], capture_output=True, text=True, check=True).stdout
            for line in nmcli_output.strip().split('\n'):
                parts = line.split(':')
                if len(parts) > 1 and parts[1].lower() != 'lo' and not parts[1].lower().startswith('tun'):
                    active_connection_name = parts[0]
                    break
            
            if active_connection_name:
                safe_print(f"  > Neutralizando la ruta por defecto de '{active_connection_name}'...")
                subprocess.run(["sudo", "nmcli", "connection", "modify", active_connection_name, "ipv4.never-default", "yes"], check=True, capture_output=True)
                subprocess.run(["sudo", "nmcli", "connection", "modify", active_connection_name, "ipv4.ignore-auto-routes", "yes"], check=True, capture_output=True)
                CONNECTION_MODIFIED = True
                safe_print(f"{GREEN}  > Perfil de '{active_connection_name}' modificado. Procediendo a conectar la VPN.{NC}")
            else:
                safe_print(f"{YELLOW}  > Advertencia: No se pudo determinar la conexión principal para neutralizar.{NC}")
        except Exception as e:
            safe_print(f"{RED}Error al preparar la conexión principal: {e}{NC}")
            safe_print(f"{YELLOW}La conexión podría ser inestable.{NC}")

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

        if ORIGINAL_DEFAULT_ROUTE_DETAILS:
            safe_print(f"{BLUE}  > Eliminando la ruta por defecto original para evitar conflictos...{NC}")
            safe_print(f"{YELLOW}    Ruta eliminada: default {ORIGINAL_DEFAULT_ROUTE_DETAILS}{NC}")
            subprocess.run(["sudo", "ip", "route", "del", "default"], check=False, capture_output=True)
        
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
        all_routes = subprocess.run(["ip", "route"], capture_output=True, text=True).stdout
        
        is_route_ok = ('0.0.0.0/1' in all_routes and '128.0.0.0/1' in all_routes and 'dev tun' in all_routes) or \
                      ('default dev tun' in all_routes)
        
        if not is_route_ok:
            safe_print(f"{RED}ESTADO: ¡DESCONECTADO! (No se encontró una ruta por defecto válida para la VPN).{NC}")
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

def route_guardian():
    global ROUTE_CORRECTION_COUNT, LAST_RECONNECTION_TIME
    
    while not GUARDIAN_STOP_EVENT.is_set():
        try:
            ip_route_output = subprocess.run(["ip", "route"], capture_output=True, text=True, check=True).stdout
            
            for line in ip_route_output.strip().split('\n'):
                if line.startswith('default') and 'dev tun' not in line:
                    
                    offending_route = line.strip()
                    safe_print(f"\n{RED}Guardián: Detectada ruta de leak: '{offending_route}'. Eliminando...{NC}")
                    command = f"sudo ip route del {offending_route}"
                    subprocess.run(command, shell=True, check=False, capture_output=True)
                    
                    ROUTE_CORRECTION_COUNT += 1
                    LAST_RECONNECTION_TIME = time.time()
                    log_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(LAST_RECONNECTION_TIME))
                    try:
                        script_dir = os.path.dirname(os.path.realpath(__file__))
                        log_path = os.path.join(script_dir, RECONNECTION_LOG_FILE)
                        with open(log_path, 'a') as f:
                            f.write(f"Corrección a las: {log_time_str}\n")
                    except Exception as e:
                        safe_print(f"{RED}Error al escribir en el log de correcciones: {e}{NC}")
                    
                    break
        except Exception:
            pass
        
        GUARDIAN_STOP_EVENT.wait(ROUTE_GUARDIAN_INTERVAL)

def monitor_connection(selected_file, selected_location, initial_ip, vpn_ip, dns_fallback_used, forwarded_port):
    global ROUTE_CORRECTION_COUNT, LAST_RECONNECTION_TIME, CONNECTION_START_TIME
    reconnection_count = 0
    last_analysis_time = 0
    analysis_result_block = None

    ROUTE_CORRECTION_COUNT = 0
    LAST_RECONNECTION_TIME = None
    
    GUARDIAN_STOP_EVENT.clear()
    guardian_thread = threading.Thread(target=route_guardian, daemon=True)
    guardian_thread.start()

    try:
        while True:
            clear_screen()
            safe_print(f"{BLUE}======================================={NC}")
            safe_print(f"{BLUE}  VPN EN FUNCIONAMIENTO (Modo Monitor){NC}")
            safe_print(f"{BLUE}======================================={NC}")

            safe_print(f"  Ubicación:         {RED}{selected_location}{NC}")

            duration_seconds = 0
            if CONNECTION_START_TIME:
                duration_seconds = time.time() - CONNECTION_START_TIME
                total_minutes, _ = divmod(int(duration_seconds), 60)
                hours, minutes = divmod(total_minutes, 60)
                safe_print(f"  Tiempo conectado:  {hours}h {minutes}m")

            safe_print(f"  IP Esperada (VPN): {GREEN}{vpn_ip}{NC}")

            port_color = GREEN if forwarded_port and forwarded_port.isdigit() else YELLOW
            port_display = forwarded_port if forwarded_port else "Obteniendo..."
            safe_print(f"  Puerto Asignado:   {port_color}{port_display}{NC}")

            reconnection_color = RED if reconnection_count > 0 else NC
            safe_print(f"  Reconexiones:      {reconnection_color}{reconnection_count}{NC}")

            if ROUTE_CORRECTION_COUNT > 0:
                safe_print(f"\n  {BLUE}--- Análisis de Estabilidad de Ruta ---{NC}")
                
                status_color = NC
                stability_metric = 0
                duration_hours = duration_seconds / 3600
                if duration_hours > 0:
                    stability_metric = ROUTE_CORRECTION_COUNT / duration_hours
                    if stability_metric <= 5: status_color = GREEN
                    elif stability_metric <= 20: status_color = YELLOW
                    else: status_color = RED

                correction_line = f"  Correcciones Ruta: {status_color}{ROUTE_CORRECTION_COUNT}{NC}"
                if LAST_RECONNECTION_TIME:
                    elapsed_seconds = int(time.time() - LAST_RECONNECTION_TIME)
                    if elapsed_seconds < 60: time_str = f"{elapsed_seconds}s"
                    elif elapsed_seconds < 3600:
                        mins, secs = divmod(elapsed_seconds, 60)
                        time_str = f"{mins}m {secs}s"
                    else:
                        hours, remainder = divmod(elapsed_seconds, 3600)
                        mins, _ = divmod(remainder, 60)
                        time_str = f"{hours}h {mins}m"
                    correction_line += f" (última hace {time_str})"
                safe_print(correction_line)

                if duration_seconds > 300:
                    safe_print(f"  Tasa Corrección:   {status_color}{stability_metric:.2f} corr./hora{NC}")

                if (ROUTE_CORRECTION_COUNT >= 4 and 
                    duration_seconds > 1800 and 
                    (time.time() - last_analysis_time) > 900 and
                    stability_metric > 5):
                    try:
                        script_dir = os.path.dirname(os.path.realpath(__file__))
                        log_path = os.path.join(script_dir, RECONNECTION_LOG_FILE)
                        timestamps = []
                        with open(log_path, 'r') as f:
                            for line in f:
                                if line.startswith("Corrección a las:"):
                                    time_str = line.replace("Corrección a las: ", "").strip()
                                    timestamps.append(datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S'))
                        
                        filtered_timestamps = []
                        if timestamps:
                            ECO_THRESHOLD_SECONDS = 3
                            filtered_timestamps.append(timestamps[0])
                            for i in range(1, len(timestamps)):
                                time_difference = (timestamps[i] - filtered_timestamps[-1]).total_seconds()
                                if time_difference > ECO_THRESHOLD_SECONDS:
                                    filtered_timestamps.append(timestamps[i])
                        
                        graph_line = ""
                        if filtered_timestamps:
                            graph_width = 40
                            seconds_per_slot = duration_seconds / graph_width
                            slots = ['.'] * graph_width
                            first_connection_time = datetime.fromtimestamp(CONNECTION_START_TIME)
                            for ts in filtered_timestamps:
                                correction_seconds_from_start = (ts - first_connection_time).total_seconds()
                                slot_index = int(correction_seconds_from_start / seconds_per_slot)
                                if 0 <= slot_index < graph_width:
                                    slots[slot_index] = f"{RED}X{GREEN}"
                            graph_content = "".join(slots)
                            graph_line = f"  Distribución:      {GREEN}[{graph_content}]{NC}"

                        pattern_analysis_line = ""
                        if len(filtered_timestamps) > 1:
                            intervals = [(filtered_timestamps[i] - filtered_timestamps[i-1]).total_seconds() for i in range(1, len(filtered_timestamps))]
                            sorted_intervals = sorted(intervals)
                            n = len(sorted_intervals)
                            mid = n // 2
                            median_seconds = (sorted_intervals[mid - 1] + sorted_intervals[mid]) / 2 if n % 2 == 0 else sorted_intervals[mid]
                            tolerance_seconds = 30
                            pattern_count = sum(1 for i in intervals if (median_seconds - tolerance_seconds) <= i <= (median_seconds + tolerance_seconds))
                            pattern_percentage = (pattern_count / len(intervals)) * 100
                            next_analysis_time_str = time.strftime('%H:%M', time.localtime(time.time() + 900))
                            next_analysis_info = f" {YELLOW}(Próximo: {next_analysis_time_str}){NC}"
                            if pattern_percentage > 50:
                                pattern_minutes = median_seconds / 60
                                line1 = f"  Análisis Patrón:   {GREEN}{pattern_percentage:.0f}% correcciones con patrón ~{pattern_minutes:.1f} min.{NC}{next_analysis_info}"
                                line2 = f"                     {GREEN}(Posiblemente es el DHCP del router){NC}"
                                pattern_analysis_line = f"{line1}\n{line2}"
                            else:
                                pattern_analysis_line = f"  Análisis Patrón:   {YELLOW}No se detecta un patrón determinado en las correcciones.{NC}{next_analysis_info}"
                        
                        current_block = ""
                        if graph_line: current_block += f"\n{graph_line}"
                        if pattern_analysis_line: current_block += f"\n{pattern_analysis_line}"
                        analysis_result_block = current_block
                        last_analysis_time = time.time()
                    except Exception:
                        pass
                
                if duration_seconds > 1800 and analysis_result_block and stability_metric > 5:
                    safe_print(analysis_result_block)

            next_check_time = time.time() + MONITOR_INTERVAL
            next_check_str = time.strftime('%H:%M:%S', time.localtime(next_check_time))
            
            cycle_seconds = MONITOR_INTERVAL
            if cycle_seconds < 60:
                cycle_str = f"{cycle_seconds}s"
            else:
                mins, secs = divmod(cycle_seconds, 60)
                cycle_str = f"{mins}m {secs}s"
            
            safe_print(f"\n  Comprobación:      {next_check_str} {YELLOW}(Ciclo: {cycle_str}){NC}\n")

            status_message = f"{GREEN}ESTADO: Conectado y verificado.{NC}"

            if check_connection_status(expected_ip=vpn_ip):
                reconnection_count += 1
                safe_print(f"\n{YELLOW}Conexión perdida. Realizando limpieza antes de reconectar...{NC}")
                
                GUARDIAN_STOP_EVENT.set()
                guardian_thread.join(timeout=2)

                cleanup(is_failure=False)
                time.sleep(3)
                
                new_ip, new_dns_fallback, new_port = establish_connection(selected_file, selected_location, initial_ip, is_reconnecting=True)
                
                if not new_ip:
                    safe_print(f"\n{RED}La reconexión ha fallado. El kill switch ha sido activado.{NC}")
                    time.sleep(5)
                    return
                
                vpn_ip, dns_fallback_used, forwarded_port = new_ip, new_dns_fallback, new_port

                safe_print(f"{BLUE}Reiniciando contadores para la nueva sesión...{NC}")
                ROUTE_CORRECTION_COUNT = 0
                LAST_RECONNECTION_TIME = None
                last_analysis_time = 0
                analysis_result_block = None

                title = "VPN Reconectada: ¡Acción Requerida!"
                message = f"El puerto ha cambiado a {forwarded_port}.\nDebes reiniciar tus aplicaciones (aMule, Transmission) para usar la nueva configuración."
                send_critical_notification(title, message)

                display_success_banner(selected_location, initial_ip, vpn_ip, True, reconnection_count)
                safe_print(f"{GREEN}Reconexión exitosa. Reanudando monitorización...{NC}")
                
                GUARDIAN_STOP_EVENT.clear()
                guardian_thread = threading.Thread(target=route_guardian, daemon=True)
                guardian_thread.start()
                
                time.sleep(4)
                continue

            safe_print(status_message)
            safe_print(f"\n{YELLOW}Presiona Ctrl+C para salir.{NC}")
            time.sleep(MONITOR_INTERVAL)
    except KeyboardInterrupt:
        safe_print(f"\n{YELLOW}Señal de salida recibida. Deteniendo al guardián de rutas...{NC}")
        GUARDIAN_STOP_EVENT.set()
        guardian_thread.join(timeout=2)
        safe_print(f"{GREEN}Guardián detenido.{NC}")

        cleanup(is_failure=False)
        
        safe_print(f"{BLUE}Reiniciando contadores para la próxima sesión...{NC}")
        ROUTE_CORRECTION_COUNT = 0
        LAST_RECONNECTION_TIME = None
        CONNECTION_START_TIME = None

        safe_print(f"\n{YELLOW}Saliendo del monitor. Volviendo al menú en 5 segundos...{NC}")
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

    safe_print(f"  {BLUE}--- Leyenda de Estabilidad (Correcciones/hora) ---{NC}")
    safe_print(f"  {GREEN}  0-5:   Normalidad{NC}")
    safe_print(f"  {YELLOW}  6-20:  Ojo (puede ser el router){NC}")
    safe_print(f"  {RED}  >20:   Alerta (conexión inestable){NC}")

def get_user_choice(locations, last_choice=None):
    safe_print(f"{BLUE}--- UBICACIONES DISPONIBLES ---{NC}")
    for i, location in enumerate(locations, 1): safe_print(f"  {i}) {location}")
    safe_print("")

    prompt = f"Elige (1-{len(locations)}): "
    if last_choice is not None:
        try:
            default_name = locations[last_choice - 1]
            prompt = f"Elige (1-{len(locations)}) o Intro para '{default_name}': "
        except IndexError:
            last_choice = None
    
    while True:
        try:
            choice_str = input(prompt)
            if not choice_str and last_choice is not None:
                return last_choice
            
            choice = int(choice_str)
            if 1 <= choice <= len(locations):
                return choice
            safe_print(f"{RED}Selección fuera de rango.{NC}")
        except ValueError:
            safe_print(f"{RED}Por favor, introduce un número válido.{NC}")
        except KeyboardInterrupt:
            GUARDIAN_STOP_EVENT.set()
            cleanup(is_failure=False)
            safe_print(f"\n{YELLOW}Operación cancelada. Saliendo del script en 5 segundos...{NC}")
            time.sleep(5)
            sys.exit(0)

def main():
    global ORIGINAL_RESOLV_CONF_BACKUP, LAST_CHOICE_FILE
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

    try:
        if os.path.exists("/etc/resolv.conf"):
            subprocess.run(["sudo", "cp", "/etc/resolv.conf", ORIGINAL_RESOLV_CONF_BACKUP], check=True)
            safe_print(f"{BLUE}Copia de seguridad de la configuración DNS creada.{NC}")
    except Exception as e:
        safe_print(f"{YELLOW}Advertencia: No se pudo crear la copia de seguridad de /etc/resolv.conf: {e}{NC}")

    safe_print(f"{BLUE}Verificando conectividad y obteniendo IP pública...{NC}")
    initial_ip = None
    try:
        res = subprocess.run(["curl", "-s", "--max-time", str(CURL_TIMEOUT), "ifconfig.me"], capture_output=True, text=True, check=True)
        ip_candidate = res.stdout.strip()
        if not is_valid_ip(ip_candidate):
            raise ValueError("Respuesta no es una IP válida")
        initial_ip = ip_candidate
        safe_print(f"{GREEN}Conectividad a Internet confirmada.{NC}")
    except Exception:
        safe_print(f"{YELLOW}No se detecta una conexión funcional. Intentando reparación automática...{NC}")
        
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
                safe_print(f"{YELLOW}  > No se encontraron conexiones activas que restaurar.{NC}")

            safe_print("  > Reiniciando la pila de red (off/on)...")
            subprocess.run(["sudo", "nmcli", "networking", "off"], check=True, capture_output=True)
            time.sleep(10)
            subprocess.run(["sudo", "nmcli", "networking", "on"], check=True, capture_output=True)
            time.sleep(15)

            safe_print("  > Verificando la conectividad después de la reparación...")
            res = subprocess.run(["curl", "-s", "--max-time", str(CURL_TIMEOUT), "ifconfig.me"], capture_output=True, text=True, check=True)
            ip_candidate = res.stdout.strip()
            if not is_valid_ip(ip_candidate):
                 raise ValueError("Respuesta no es una IP válida tras reparación")
            initial_ip = ip_candidate
            safe_print(f"{GREEN}¡Éxito! La conexión a Internet ha sido restaurada.{NC}")
            time.sleep(4)
        except Exception as e:
            safe_print(f"\r\033[K{RED}Error Crítico: La reparación automática falló.{NC}")
            safe_print(f"{YELLOW}El problema parece ser externo al script (ej. Wi-Fi desconectado, sin señal, fallo del ISP).{NC}")
            safe_print(f"Error detallado: {e}")
            cleanup(is_failure=False)
            safe_print(f"\n{YELLOW}El script se cerrará en 15 segundos...{NC}")
            time.sleep(15)
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

    while True:
        clear_screen()
        safe_print(f"{BLUE}======================================={NC}")
        safe_print(f"{BLUE}    Asistente de Conexión VPN")
        safe_print(f"{BLUE}======================================={NC}")
        safe_print(f"\nDirectorio: {script_dir}\nIP Original: {YELLOW}{initial_ip}{NC}\n")

        last_choice_from_file = None
        last_choice_path = os.path.join(script_dir, LAST_CHOICE_FILE)
        if os.path.exists(last_choice_path):
            try:
                with open(last_choice_path, 'r') as f:
                    content = f.read().strip()
                    if content.isdigit():
                        potential_choice = int(content)
                        if 1 <= potential_choice <= len(locations):
                            last_choice_from_file = potential_choice
            except Exception:
                pass 

        choice = get_user_choice(locations, last_choice_from_file)
        
        try:
            with open(last_choice_path, 'w') as f:
                f.write(str(choice))
        except Exception as e:
            safe_print(f"{YELLOW}Advertencia: No se pudo guardar la última selección: {e}{NC}")

        selected_file, selected_location = ovpn_files[choice - 1], locations[choice - 1]

        new_ip, dns_fallback_used, forwarded_port = establish_connection(selected_file, selected_location, initial_ip)
        
        if new_ip:
            safe_print(f"{GREEN}Conexión verificada. Mostrando resumen en 10 segundos...{NC}")
            time.sleep(10)

            display_success_banner(selected_location, initial_ip, new_ip)
            time.sleep(12)
            monitor_connection(selected_file, selected_location, initial_ip, new_ip, dns_fallback_used, forwarded_port)
        else:
            safe_print(f"\n{YELLOW}Volviendo al menú en 5 segundos...{NC}")
            time.sleep(5)

if __name__ == "__main__":
    if "--run-in-terminal" not in sys.argv:
        script_path = os.path.realpath(__file__)
        terminals = {"gnome-terminal": "--", "konsole": "-e", "xfce4-terminal": "--hold -e", "xterm": "-e"}
        for term, args in terminals.items():
            if which(term):
                try:
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
            GUARDIAN_STOP_EVENT.set()
            cleanup(is_failure=False)
            safe_print(f"\n{YELLOW}Script finalizado por el usuario. Saliendo en 5 segundos...{NC}")
            time.sleep(5)
        except Exception as e:
            GUARDIAN_STOP_EVENT.set()
            cleanup(is_failure=True)
            safe_print(f"\n{RED}Error inesperado: {e}{NC}")
            time.sleep(5)
            sys.exit(1)
