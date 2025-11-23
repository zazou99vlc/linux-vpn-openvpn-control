#!/usr/bin/env python3
import os
import subprocess
import time
import sys
import threading
import re
import json
import base64
import getpass
from shutil import which
from datetime import datetime

# --- GESTIÓN DE ERRORES DE IMPORTACIÓN (BILINGÜE) ---
try:
    import ping3
    ping3.EXCEPTIONS = True
    import requests
except ImportError as e:
    missing_lib = str(e).split("'")[1]
    print(f"\033[1;31m[ERROR] Library '{missing_lib}' missing / Falta la librería '{missing_lib}'.\033[0m")
    print(f"\033[1;33mRun / Ejecute: pip install {missing_lib}\033[0m")
    time.sleep(5)
    sys.exit(1)

# --- COLORES Y CONSTANTES ---
BLUE = "\033[1;34m"
YELLOW = "\033[1;33m"
GREEN = "\033[1;32m"
RED = "\033[1;31m"
NC = "\033[0m"

LOG_FILE = "openvpn.log"
PORT_FILE = "forwarded_port.txt"
CONFIG_FILE = "config.json" 
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
ANALYSIS_INTERVAL = 600
ANALYSIS_MIN_DURATION = 1800
MAX_LOCATION_NAME_LENGTH = 15

# --- VARIABLES GLOBALES ---
ORIGINAL_DEFAULT_ROUTE_DETAILS = None
ROUTE_CORRECTION_COUNT = 0
ORIGINAL_RESOLV_CONF_BACKUP = "/tmp/resolv.conf.original.bak"
CONNECTION_MODIFIED = False
GUARDIAN_STOP_EVENT = threading.Event()
RECONNECTION_LOG_FILE = "reconnections.log"
CONNECTION_START_TIME = None
LAST_RECONNECTION_TIME = None
CURRENT_LANG = "es" 

# --- DICCIONARIO DE IDIOMAS ---
L_WIDTH = 22 

TRANSLATIONS = {
    "es": {
        "closing": "El script se cerrará en 10 segundos...",
        "sudo_simple": "Se solicitará acceso de administrador (sudo) para ejecutar\nOpenVPN y gestionar la red.",
        "sudo_error": "Error: No se pudo obtener privilegios de sudo.",
        "term_error": "No se detectó un terminal compatible.",
        "term_run": "Ejecuta: python3 '{}' --run-in-terminal",
        "ctrl_c_exit": "Ctrl+C -> Salir",
        "final_exit": "Saliendo en 5 segundos...",
        "clean_start": "Iniciando secuencia de limpieza...",
        "restoring_net": "Realizando restauración de red completa...",
        "restoring_dns": "  > Restaurando configuración de DNS original...",
        "restoring_nm": "  > Usando NetworkManager para restaurar la conexión '{}'...",
        "nm_step1": "    - Paso 1: Restaurando permisos del perfil...",
        "nm_step2": "    - Paso 2: Pidiendo a NetworkManager que reactive la conexión...",
        "nm_step3": "    - Paso 3: Esperando 5 segundos a que la red se estabilice...",
        "nm_success": "    ¡Éxito! NetworkManager ha restaurado la conexión y la ruta por defecto.",
        "nm_fail_route": "    ¡ATENCIÓN! La reactivación no estableció una ruta por defecto.",
        "nm_crit_error": "    Error crítico restaurando conexión: {}",
        "nm_manual": "    Reinicia la red manualmente: sudo nmcli networking off && sudo nmcli networking on",
        "clean_complete": "Limpieza completada.",
        "net_disabled": "IMPORTANTE: La red ha sido DESACTIVADA.",
        "reactivate_cmd": "Para reactivarla: sudo nmcli networking on",
        "kill_switch_active": "¡Corte de emergencia! Red desactivada para proteger tu IP.",
        "kill_switch_recover": "Para recuperar la conexión, simplemente vuelve a ejecutar este script.",
        "notif_title_crit": "FALLO CRÍTICO DE VPN",
        "notif_msg_kill": "Corte de emergencia activado. Ejecuta el script de nuevo para recuperar.",
        "pass_perm_warn": "Advertencia de Seguridad",
        "pass_perm_msg": "El archivo '{}' tiene permisos inseguros.\nEjecuta: chmod 600 {}",
        "notif_reconn_title": "VPN Reconectada: ¡Atención!",
        "notif_reconn_msg": "El puerto ha cambiado a {}.\nReinicia tus aplicaciones P2P.",
        "route_check": "Verificando y estableciendo ruta por defecto a la VPN...",
        "tun_error": "  Error: No se encontró interfaz TUN activa.",
        "route_success": "  Ruta por defecto establecida a {}.",
        "route_exists": "  La ruta a {} ya existe. Continuando...",
        "conn_lost_retry": "Se ha perdido la conexión. Intentando reconectar...",
        "connecting_to": "Conectando a {}...",
        "orig_route_detect": "Ruta original detectada: default {}",
        "prep_net": "Preparando red principal para la VPN...",
        "neutralize_route": "  > Neutralizando ruta de '{}'...",
        "profile_mod": "  > Perfil '{}' modificado. Conectando VPN.",
        "start_attempt": "Iniciando conexión (Intento {}/{})...",
        "ovpn_started": "Proceso OpenVPN iniciado.",
        "attempt_fail": "Intento {} fallido.",
        "fail_banner_wait": "Fallo al iniciar OpenVPN. Resumen en 3 segundos...",
        "stabilizing": "Estabilizando y verificando red...",
        "check_ping": "Verificando conectividad (ping 1.1.1.1)...",
        "ping_ok": "Verificando conectividad (ping 1.1.1.1)... OK.",
        "ping_fail": "Verificando conectividad (ping 1.1.1.1)... FALLO.",
        "check_ip": "Verificando IP (Intento {}/{})...",
        "dns_fallback": "Fallo de IP. Iniciando fallback de DNS...",
        "dns_temp": "DNS público añadido. Reintentando...",
        "dns_restored": "DNS original restaurado.",
        "dns_success": "¡Éxito! Conexión establecida con DNS de fallback.",
        "ip_fail_banner": "Fallo verificación IP. Resumen en 3 segundos...",
        "get_port": "Conexión verificada. Obteniendo puerto...",
        "port_saved": "Puerto {} guardado en '{}'.",
        "del_orig_route": "  > Eliminando ruta original para evitar conflictos...",
        "conn_cancel": "Conexión cancelada por usuario.",
        "status_disconnected": "ESTADO: ¡DESCONECTADO! (OpenVPN no encontrado).",
        "status_route_fail": "ESTADO: ¡DESCONECTADO! (Sin ruta válida).",
        "status_ip_fail": "ESTADO: ¡DESCONECTADO! (IP pública es {}).",
        "guardian_leak": "Guardián: Ruta Leak detectada y eliminada.\n{}",
        "mon_header": "  VPN EN FUNCIONAMIENTO (Modo Monitor)",
        "lbl_location": "Ubicación:".ljust(L_WIDTH),
        "lbl_time": "Tiempo conectado:".ljust(L_WIDTH),
        "lbl_ip": "IP Esperada (VPN):".ljust(L_WIDTH),
        "lbl_port": "Puerto Asignado:".ljust(L_WIDTH),
        "lbl_reconn": "Reconexiones:".ljust(L_WIDTH),
        "lbl_route_corr": "Correcciones Ruta:".ljust(L_WIDTH),
        "lbl_corr_rate": "Tasa Corrección:".ljust(L_WIDTH),
        "lbl_dist": "Distribución:".ljust(L_WIDTH),
        "lbl_pattern": "Análisis Patrón:".ljust(L_WIDTH),
        "lbl_check": "Comprobación:".ljust(L_WIDTH),
        "ana_header": "--- Análisis de Estabilidad de Ruta ---",
        "ana_pattern_yes": "{}% correcciones con patrón ~{:.1f} min.",
        "ana_pattern_router": "(Posiblemente DHCP del router)",
        "ana_pattern_no": "No se detecta patrón en las correcciones.",
        "status_ok": "ESTADO: Conectado y verificado.",
        "reconn_fail_kill": "Reconexión fallida. Corte de emergencia activado.",
        "reconn_success": "Reconexión exitosa. Monitorizando...",
        "exit_mon": "Saliendo del monitor. Menú en 5 segundos...",
        "fail_title": "❌ FALLO DE CONEXIÓN",
        "fail_msg_attempts": "No se pudo conectar tras {} intentos.",
        "fail_msg_tunnel": "Fallo de conectividad. El túnel no enruta.",
        "fail_msg_ip": "La IP no cambió (incluso con DNS fallback).",
        "fail_msg_route": "Fallo al establecer ruta por defecto.",
        "succ_title": "✔ CONEXIÓN ESTABLECIDA",
        "succ_orig_ip": "IP Original:",
        "succ_vpn_ip": "IP VPN:",
        "legend_title": "--- Leyenda de Estabilidad (Correcciones/hora) ---",
        "legend_1": "  0-5:   Normalidad",
        "legend_2": "  6-20:  Ojo (puede ser el router)",
        "legend_3": "  >20:   Alerta (conexión inestable)",
        "menu_avail": "--- UBICACIONES DISPONIBLES ---",
        "menu_none": "No se encontraron ubicaciones.",
        "menu_prompt": "Elige (1-{}), Intro para '{}', o 'M' Menú: ",
        "menu_prompt_no_def": "Elige (1-{}), o 'M' Menú: ",
        "welcome_title": "Bienvenido al Asistente de Conexión VPN",
        "guide_title": "--- Guía Rápida ---",
        "guide_1": "1. Copia tus archivos .ovpn en esta carpeta.",
        "guide_2": "2. No necesitas modificar nada. El script inyecta las\n   configuraciones necesarias al vuelo.",
        "guide_3": "3. Configura tus credenciales en el menú (M) o al\n   iniciar la conexión por primera vez.",
        "guide_4": "4. Sal siempre con Ctrl+C. Si pierdes red, reinicia el script.",
        "check_conn": "Verificando conectividad e IP pública...",
        "conn_confirmed": "Conectividad confirmada.",
        "repair_attempt": "Sin conexión. Intentando reparación automática...",
        "repair_restoring": "  > Restaurando NetworkManager...",
        "repair_reset": "  > Reiniciando pila de red (off/on)...",
        "repair_verify": "  > Verificando tras reparación...",
        "repair_success": "¡Éxito! Conexión restaurada.",
        "repair_fail": "Error Crítico: Reparación fallida.",
        "repair_fail_ext": "Problema externo al script (ej. Wi-Fi caído).",
        "err_no_ovpn": "No se encontraron archivos .ovpn",
        "err_no_pass": "Error: No se encuentra 'pass.txt' en '{}'.",
        "menu_main_title": "Asistente de Conexión VPN",
        "select_lang": "Seleccione Idioma / Select Language",
        "lang_saved": "Idioma guardado / Language saved: {}",
        "last_ago": " (última hace {})",
        "menu_config_title": "Configuración y Herramientas",
        "menu_opt_display": "Configurar Visualización de Nombres",
        "menu_opt_lang": "Cambiar Idioma",
        "menu_opt_creds": "Configurar Credenciales VPN",
        "menu_opt_back": "Volver",
        "cfg_fmt_q": "¿Qué formato prefieres?",
        "cfg_fmt_a": "A) [País] Ciudad (ej: [US] Miami)",
        "cfg_fmt_b": "B) Solo Ciudad (ej: Miami)",
        "cfg_sep_q": "Separador (Intro para '-'): ",
        "cfg_idx_city": "¿Qué número es la Ciudad?: ",
        "cfg_idx_country": "¿Qué número es el País?: ",
        "cfg_saved": "Configuración guardada.",
        "cfg_sample": "Archivo de ejemplo: ",
        "cfg_parts": "Partes detectadas:",
        "cfg_err_idx": "Índice inválido.",
        "cfg_err_empty": "No hay archivos .ovpn para usar de ejemplo.",
        "cfg_creds_title": "Configurar Credenciales VPN",
        "cfg_creds_info": "Estas credenciales se guardarán localmente protegidas.",
        "cfg_user": "Usuario VPN: ",
        "cfg_pass": "Contraseña VPN: ",
        "cfg_creds_saved": "Credenciales guardadas y protegidas.",
        "cfg_creds_err": "Datos inválidos. No se guardó nada.",
        "err_no_creds": "Error: No hay credenciales configuradas."
    },
    "en": {
        "closing": "Script will close in 10 seconds...",
        "sudo_simple": "Administrator access (sudo) will be requested to run\nOpenVPN and manage the network.",
        "sudo_error": "Error: Could not get sudo privileges.",
        "term_error": "No compatible terminal found.",
        "term_run": "Run: python3 '{}' --run-in-terminal",
        "ctrl_c_exit": "Ctrl+C -> Exit",
        "final_exit": "Exiting in 5 seconds...",
        "clean_start": "Starting cleanup sequence...",
        "restoring_net": "Performing full network restoration...",
        "restoring_dns": "  > Restoring original DNS configuration...",
        "restoring_nm": "  > Using NetworkManager to restore connection '{}'...",
        "nm_step1": "    - Step 1: Restoring profile permissions...",
        "nm_step2": "    - Step 2: Requesting connection reactivation...",
        "nm_step3": "    - Step 3: Waiting 5 seconds for network to stabilize...",
        "nm_success": "    Success! NetworkManager restored connection and default route.",
        "nm_fail_route": "    WARNING! Reactivation did not establish a default route.",
        "nm_crit_error": "    Critical error restoring connection: {}",
        "nm_manual": "    Restart network manually: sudo nmcli networking off && sudo nmcli networking on",
        "clean_complete": "Cleanup complete.",
        "net_disabled": "IMPORTANT: Network has been DISABLED.",
        "reactivate_cmd": "To reactivate: sudo nmcli networking on",
        "kill_switch_active": "Emergency cut! Network disabled to protect your IP.",
        "kill_switch_recover": "To restore connection, simply run this script again.",
        "notif_title_crit": "CRITICAL VPN FAILURE",
        "notif_msg_kill": "Emergency cut activated. Run script again to recover.",
        "pass_perm_warn": "Security Warning",
        "pass_perm_msg": "File '{}' has insecure permissions.\nRun: chmod 600 {}",
        "notif_reconn_title": "VPN Reconnected: Attention!",
        "notif_reconn_msg": "Port changed to {}.\nRestart your P2P apps.",
        "route_check": "Verifying and setting default route to VPN...",
        "tun_error": "  Error: No active TUN interface found.",
        "route_success": "  Default route set to {}.",
        "route_exists": "  Route to {} already exists. Continuing...",
        "conn_lost_retry": "Connection lost. Attempting to reconnect...",
        "connecting_to": "Connecting to {}...",
        "orig_route_detect": "Original route detected: default {}",
        "prep_net": "Preparing main network for VPN...",
        "neutralize_route": "  > Neutralizing route of '{}'...",
        "profile_mod": "  > Profile '{}' modified. Connecting VPN.",
        "start_attempt": "Starting connection (Attempt {}/{})...",
        "ovpn_started": "OpenVPN process started.",
        "attempt_fail": "Attempt {} failed.",
        "fail_banner_wait": "Failed to start OpenVPN. Summary in 3 seconds...",
        "stabilizing": "Stabilizing and verifying network...",
        "check_ping": "Verifying connectivity (ping 1.1.1.1)...",
        "ping_ok": "Verifying connectivity (ping 1.1.1.1)... OK.",
        "ping_fail": "Verifying connectivity (ping 1.1.1.1)... FAILED.",
        "check_ip": "Verifying IP (Attempt {}/{})...",
        "dns_fallback": "IP failed. Starting DNS fallback...",
        "dns_temp": "Public DNS added. Retrying...",
        "dns_restored": "Original DNS restored.",
        "dns_success": "Success! Connection established via DNS fallback.",
        "ip_fail_banner": "IP verification failed. Summary in 3 seconds...",
        "get_port": "Connection verified. Getting port...",
        "port_saved": "Port {} saved to '{}'.",
        "del_orig_route": "  > Removing original route to prevent conflicts...",
        "conn_cancel": "Connection cancelled by user.",
        "status_disconnected": "STATUS: DISCONNECTED! (OpenVPN not found).",
        "status_route_fail": "STATUS: DISCONNECTED! (No valid route).",
        "status_ip_fail": "STATUS: DISCONNECTED! (Public IP is {}).",
        "guardian_leak": "Guardian: Leak route detected and deleted.\n{}",
        "mon_header": "  VPN RUNNING (Monitor Mode)",
        "lbl_location": "Location:".ljust(L_WIDTH),
        "lbl_time": "Connected Time:".ljust(L_WIDTH),
        "lbl_ip": "Expected IP (VPN):".ljust(L_WIDTH),
        "lbl_port": "Assigned Port:".ljust(L_WIDTH),
        "lbl_reconn": "Reconnections:".ljust(L_WIDTH),
        "lbl_route_corr": "Route Corrections:".ljust(L_WIDTH),
        "lbl_corr_rate": "Correction Rate:".ljust(L_WIDTH),
        "lbl_dist": "Distribution:".ljust(L_WIDTH),
        "lbl_pattern": "Pattern Analysis:".ljust(L_WIDTH),
        "lbl_check": "Next Check:".ljust(L_WIDTH),
        "ana_header": "--- Route Stability Analysis ---",
        "ana_pattern_yes": "{}% corrections with pattern ~{:.1f} min.",
        "ana_pattern_router": "(Possibly router DHCP)",
        "ana_pattern_no": "No pattern detected in corrections.",
        "status_ok": "STATUS: Connected and verified.",
        "reconn_fail_kill": "Reconnection failed. Emergency cut activated.",
        "reconn_success": "Reconnection successful. Monitoring...",
        "exit_mon": "Exiting monitor. Menu in 5 seconds...",
        "fail_title": "❌ CONNECTION FAILURE",
        "fail_msg_attempts": "Could not connect after {} attempts.",
        "fail_msg_tunnel": "Connectivity failure. Tunnel not routing.",
        "fail_msg_ip": "IP did not change (even with DNS fallback).",
        "fail_msg_route": "Failed to set default route.",
        "succ_title": "✔ CONNECTION ESTABLISHED",
        "succ_orig_ip": "Original IP:",
        "succ_vpn_ip": "VPN IP:",
        "legend_title": "--- Stability Legend (Corrections/hour) ---",
        "legend_1": "  0-5:   Normal",
        "legend_2": "  6-20:  Watch out (router issue?)",
        "legend_3": "  >20:   Alert (unstable connection)",
        "menu_avail": "--- AVAILABLE LOCATIONS ---",
        "menu_none": "No locations found.",
        "menu_prompt": "Choose (1-{}), Enter for '{}', or 'M' Menu: ",
        "menu_prompt_no_def": "Choose (1-{}), or 'M' Menu: ",
        "welcome_title": "Welcome to the VPN Connection Assistant",
        "guide_title": "--- Quick Guide ---",
        "guide_1": "1. Copy your .ovpn files into this folder.",
        "guide_2": "2. No modification needed. The script injects necessary\n   configurations on the fly.",
        "guide_2b": "",
        "guide_3": "3. Configure credentials in the menu (M) or upon\n   first connection attempt.",
        "guide_4": "4. Always exit via Ctrl+C. If network is lost, restart script.",
        "check_conn": "Verifying connectivity and public IP...",
        "conn_confirmed": "Connectivity confirmed.",
        "repair_attempt": "No connection. Attempting auto-repair...",
        "repair_restoring": "  > Restoring NetworkManager...",
        "repair_reset": "  > Restarting network stack (off/on)...",
        "repair_verify": "  > Verifying after repair...",
        "repair_success": "Success! Connection restored.",
        "repair_fail": "Critical Error: Repair failed.",
        "repair_fail_ext": "Problem external to script (e.g. Wi-Fi down).",
        "err_no_ovpn": "No .ovpn files found",
        "err_no_pass": "Error: 'pass.txt' not found in '{}'.",
        "menu_main_title": "VPN Connection Assistant",
        "select_lang": "Seleccione Idioma / Select Language",
        "lang_saved": "Idioma guardado / Language saved: {}",
        "last_ago": " (last {} ago)",
        "menu_config_title": "Configuration & Tools",
        "menu_opt_display": "Configure Name Display",
        "menu_opt_lang": "Change Language",
        "menu_opt_creds": "Configure VPN Credentials",
        "menu_opt_back": "Back",
        "cfg_fmt_q": "Which format do you prefer?",
        "cfg_fmt_a": "A) [Country] City (e.g., [US] Miami)",
        "cfg_fmt_b": "B) City Only (e.g., Miami)",
        "cfg_sep_q": "Separator (Enter for '-'): ",
        "cfg_idx_city": "Which number is the City?: ",
        "cfg_idx_country": "Which number is the Country?: ",
        "cfg_saved": "Configuration saved.",
        "cfg_sample": "Sample file: ",
        "cfg_parts": "Detected parts:",
        "cfg_err_idx": "Invalid index.",
        "cfg_err_empty": "No .ovpn files found for sample.",
        "cfg_creds_title": "Configure VPN Credentials",
        "cfg_creds_info": "These credentials will be saved locally and protected.",
        "cfg_user": "VPN User: ",
        "cfg_pass": "VPN Password: ",
        "cfg_creds_saved": "Credentials saved and protected.",
        "cfg_creds_err": "Invalid data. Nothing saved.",
        "err_no_creds": "Error: No credentials configured."
    }
}

# --- GESTIÓN DE CONFIGURACIÓN E IDIOMA ---
class ConfigManager:
    def __init__(self, script_dir):
        self.config_path = os.path.join(script_dir, CONFIG_FILE)
        self.config = self.load_config()

    def load_config(self):
        config = {"language": None, "last_choice": None}
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    data = json.load(f)
                    config.update(data)
            except Exception:
                pass
        return config

    def save_config(self):
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f)
        except Exception:
            pass

    def set_language(self, lang):
        self.config["language"] = lang
        self.save_config()

    def set_last_choice(self, choice):
        self.config["last_choice"] = choice
        self.save_config()

    def get_language(self):
        return self.config.get("language")

    def get_last_choice(self):
        return self.config.get("last_choice")
    
    def update_display_config(self, fmt, sep, city_idx, country_idx=None):
        self.config["display_configured"] = True
        self.config["display_format"] = fmt
        self.config["separator"] = sep
        self.config["city_index"] = city_idx
        self.config["country_index"] = country_idx
        self.save_config()

    def set_credentials(self, user, password):
        self.config["vpn_user"] = base64.b64encode(user.encode()).decode()
        self.config["vpn_pass"] = base64.b64encode(password.encode()).decode()
        self.save_config()
        os.chmod(self.config_path, 0o600)

    def get_credentials(self):
        u = self.config.get("vpn_user")
        p = self.config.get("vpn_pass")
        if u and p:
            try:
                return base64.b64decode(u).decode(), base64.b64decode(p).decode()
            except Exception:
                return None, None
        return None, None

def T(key, *args):
    lang_dict = TRANSLATIONS.get(CURRENT_LANG, TRANSLATIONS["es"])
    text = lang_dict.get(key, key)
    if args:
        try:
            return text.format(*args)
        except IndexError:
            return text
    return text

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
        safe_print(f"{RED}Error: {e}{NC}")
    return None

def get_vpn_internal_ip():
    try:
        ip_addr_output = subprocess.run(["ip", "addr"], capture_output=True, text=True, check=True).stdout
        match = re.search(r"inet\s+([\d\.]+)/[\d]+\s+scope\s+global\s+(tun\d+)", ip_addr_output)
        if match:
            return match.group(1)
    except Exception as e:
        safe_print(f"{RED}  > Error: {e}{NC}")
    return None

def get_forwarded_port(internal_ip):
    if not internal_ip:
        return None
    
    api_url = f"https://connect.pvdatanet.com/v3/Api/port?ip[]={internal_ip}"
    for attempt in range(1, 4):
        try:
            safe_print(f"{YELLOW}{T('get_port')} ({attempt}/3)...{NC}", dynamic=True)
            response = requests.get(api_url, timeout=API_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            
            if data.get("supported") is True and "status" in data:
                status_text = data["status"]
                port_match = re.search(r'\d+', status_text)
                if port_match:
                    port = port_match.group(0)
                    safe_print(f"{GREEN}{T('lbl_port').strip()} {port}{NC}")
                    return port
            else:
                safe_print(f"{YELLOW}N/A{NC}")
                return "No Soportado"
        except requests.exceptions.RequestException:
            if attempt < 3:
                time.sleep(2)
            else:
                safe_print(f"{RED}API Error{NC}")
        except Exception:
            safe_print(f"{RED}API Error{NC}")
    
    return "No Disponible"

def parse_location_name(filename, config):
    base_name = filename.replace('.ovpn', '')
    
    if not config.get("display_configured"):
        parsed_name = base_name
    else:
        sep = config.get("separator", "-")
        parts = base_name.split(sep)
        
        city_idx = config.get("city_index")
        country_idx = config.get("country_index")
        fmt = config.get("display_format")
        
        city = parts[city_idx] if city_idx is not None and 0 <= city_idx < len(parts) else "?"
        
        if fmt == 'A':
            country = parts[country_idx] if country_idx is not None and 0 <= country_idx < len(parts) else "?"
            parsed_name = f"[{country}] {city}"
        else:
            parsed_name = city

    if len(parsed_name) > MAX_LOCATION_NAME_LENGTH:
        return parsed_name[:MAX_LOCATION_NAME_LENGTH - 3] + "..."
    else:
        return parsed_name

def cleanup(is_failure=False):
    global ORIGINAL_DEFAULT_ROUTE_DETAILS, ORIGINAL_RESOLV_CONF_BACKUP, CONNECTION_MODIFIED
    safe_print(f"\n{YELLOW}{T('clean_start')}{NC}")

    if CONNECTION_MODIFIED:
        safe_print(f"{BLUE}{T('restoring_net')}{NC}")
        
        subprocess.run(["sudo", "killall", "-q", "openvpn"], capture_output=True)
        time.sleep(1)

        if os.path.exists(ORIGINAL_RESOLV_CONF_BACKUP):
            safe_print(f"{T('restoring_dns')}")
            try:
                subprocess.run(["sudo", "mv", ORIGINAL_RESOLV_CONF_BACKUP, "/etc/resolv.conf"], check=True)
            except Exception as e:
                safe_print(f"{RED}    ERROR: {e}{NC}")

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
            safe_print(f"{BLUE}{T('restoring_nm', discovered_active_connection)}{NC}")
            try:
                safe_print(T('nm_step1'))
                subprocess.run(["sudo", "nmcli", "connection", "modify", discovered_active_connection, "ipv4.never-default", "no"], check=True, capture_output=True)
                subprocess.run(["sudo", "nmcli", "connection", "modify", discovered_active_connection, "ipv4.ignore-auto-routes", "no"], check=True, capture_output=True)
                
                safe_print(T('nm_step2'))
                subprocess.run(["sudo", "nmcli", "connection", "up", discovered_active_connection], check=True, capture_output=True)
                
                safe_print(f"{BLUE}{T('nm_step3')}{NC}")
                time.sleep(5)
                final_route = get_current_default_route_details()
                if final_route:
                    safe_print(f"{GREEN}{T('nm_success')}{NC}")
                    safe_print(f"{GREEN}      default {final_route}{NC}")
                else:
                    safe_print(f"{RED}{T('nm_fail_route')}{NC}")
            except Exception as e:
                safe_print(f"{RED}{T('nm_crit_error', e)}{NC}")
                safe_print(f"{YELLOW}{T('nm_manual')}{NC}")
        else:
            safe_print(f"{YELLOW}  > N/A{NC}")

    if is_failure:
        safe_print(f"{RED}{T('kill_switch_active')}{NC}")
        subprocess.run(["sudo", "nmcli", "networking", "off"], capture_output=True, text=True)
        send_critical_notification(T("notif_title_crit"), T("notif_msg_kill"))

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
    
    safe_print(f"\n{GREEN}{T('clean_complete')}{NC}")
    if is_failure:
        safe_print(f"{YELLOW}{T('net_disabled')}{NC}")
        safe_print(f"{T('kill_switch_recover')}")

def keep_sudo_alive():
    while True:
        subprocess.run(["sudo", "-v"], capture_output=True)
        time.sleep(60)

def check_and_set_default_route():
    safe_print(f"{BLUE}{T('route_check')}{NC}")
    tun_interface = None
    try:
        interfaces_output = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True).stdout
        match = re.search(r'\d+:\s*(tun\d+):', interfaces_output)
        if match:
            tun_interface = match.group(1)
        else:
            safe_print(f"{RED}{T('tun_error')}{NC}")
            return False
    except Exception as e:
        safe_print(f"{RED}  Error: {e}{NC}")
        return False

    try:
        subprocess.run(["sudo", "ip", "route", "add", "default", "dev", tun_interface], check=True, stderr=subprocess.DEVNULL)
        safe_print(f"{GREEN}{T('route_success', tun_interface)}{NC}")
    except subprocess.CalledProcessError:
        safe_print(f"{YELLOW}{T('route_exists', tun_interface)}{NC}")
    except Exception as e:
        safe_print(f"{RED}  Error: {e}{NC}")
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
                f.write(f"Time: {start_time_str}\n")
        except Exception as e:
            safe_print(f"{RED}Log Error: {e}{NC}")

        clear_screen()
        msg = T("conn_lost_retry") if is_reconnecting else T("connecting_to", selected_location)
        safe_print(f"{YELLOW}{msg}{NC}\n")

        script_dir = os.path.dirname(os.path.realpath(__file__))
        log_file_path = os.path.join(script_dir, LOG_FILE)

        if not is_reconnecting:
            ORIGINAL_DEFAULT_ROUTE_DETAILS = get_current_default_route_details()
            if ORIGINAL_DEFAULT_ROUTE_DETAILS:
                safe_print(f"{BLUE}{T('orig_route_detect', ORIGINAL_DEFAULT_ROUTE_DETAILS)}{NC}")
            else:
                safe_print(f"{RED}Error: Route?{NC}")
                return None, False, None

        safe_print(f"\n{BLUE}{T('prep_net')}{NC}")
        try:
            active_connection_name = None
            nmcli_output = subprocess.run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"], capture_output=True, text=True, check=True).stdout
            for line in nmcli_output.strip().split('\n'):
                parts = line.split(':')
                if len(parts) > 1 and parts[1].lower() != 'lo' and not parts[1].lower().startswith('tun'):
                    active_connection_name = parts[0]
                    break
            
            if active_connection_name:
                safe_print(f"{T('neutralize_route', active_connection_name)}")
                subprocess.run(["sudo", "nmcli", "connection", "modify", active_connection_name, "ipv4.never-default", "yes"], check=True, capture_output=True)
                subprocess.run(["sudo", "nmcli", "connection", "modify", active_connection_name, "ipv4.ignore-auto-routes", "yes"], check=True, capture_output=True)
                CONNECTION_MODIFIED = True
                safe_print(f"{GREEN}{T('profile_mod', active_connection_name)}{NC}")
            else:
                safe_print(f"{YELLOW}  > Warning: No active connection found.{NC}")
        except Exception as e:
            safe_print(f"{RED}Error: {e}{NC}")

        # --- GESTIÓN DE CREDENCIALES ---
        config_mgr = ConfigManager(script_dir)
        vpn_user, vpn_pass = config_mgr.get_credentials()
        
        if not vpn_user or not vpn_pass:
            safe_print(f"{RED}{T('err_no_creds')}{NC}")
            return None, False, None

        auth_data = f"{vpn_user}\n{vpn_pass}".encode('utf-8')

        for attempt in range(1, CONNECTION_ATTEMPTS + 1):
            safe_print(f"{BLUE}{T('start_attempt', attempt, CONNECTION_ATTEMPTS)}{NC}", dynamic=True)
            subprocess.run(["sudo", "killall", "-q", "openvpn"], capture_output=True)
            try:
                with open(log_file_path, "wb") as log:
                    config_path = os.path.join(script_dir, selected_file)
                    
                    # --- INYECCIÓN NINJA Y PARÁMETROS EXTRA ---
                    cmd = ["sudo", "openvpn", "--cd", script_dir, "--config", config_path, 
                           "--auth-user-pass", "/dev/stdin",
                           "--mssfix", "1450",
                           "--mute-replay-warnings"]
                    
                    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=log, stderr=log)
                    
                    try:
                        proc.stdin.write(auth_data)
                        proc.stdin.close()
                    except Exception:
                        pass
            except Exception as e:
                safe_print(f"{RED}Error: {e}{NC}")
                return None, False, None
            
            start_time, success = time.time(), False
            while time.time() - start_time < CONNECTION_TIMEOUT:
                if os.path.exists(log_file_path) and "Initialization Sequence Completed" in open(log_file_path, "r", errors='ignore').read():
                    success = True
                    break
                time.sleep(1)
                
            if success:
                safe_print(f"{GREEN}{T('ovpn_started')}{NC}")
                break
            
            safe_print(f"{RED}{T('attempt_fail', attempt)}{NC}")
            if attempt < CONNECTION_ATTEMPTS: time.sleep(RETRY_DELAY)

        if not success:
            safe_print(f"{YELLOW}{T('fail_banner_wait')}{NC}")
            time.sleep(3)
            display_failure_banner(T("fail_msg_attempts", CONNECTION_ATTEMPTS))
            cleanup(is_failure=is_reconnecting)
            return None, False, None

        safe_print(f"\n{BLUE}{T('stabilizing')}{NC}")
        time.sleep(3)
        
        safe_print(f"{YELLOW}{T('check_ping')}{NC}", dynamic=True)
        try:
            ping3.ping("1.1.1.1", timeout=PING_TIMEOUT)
            safe_print(f"{GREEN}{T('ping_ok')}{NC}")
        except Exception as e:
            safe_print(f"{YELLOW}FAIL.{NC}")
            time.sleep(3)
            safe_print(f"{RED}{T('ping_fail')}{NC}")
            display_failure_banner(T("fail_msg_tunnel"))
            cleanup(is_failure=is_reconnecting)
            return None, False, None

        new_ip, ip_verified, dns_fallback_used = "N/A", False, False
        for attempt in range(1, IP_VERIFY_ATTEMPTS + 1):
            safe_print(f"{YELLOW}{T('check_ip', attempt, IP_VERIFY_ATTEMPTS)}{NC}", dynamic=True)
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
            safe_print(f"\n{YELLOW}{T('dns_fallback')}{NC}")
            resolv_path, resolv_backup_path = "/etc/resolv.conf", "/tmp/resolv.conf.convpn.bak"
            try:
                if os.path.exists(resolv_path):
                    subprocess.run(["sudo", "cp", resolv_path, resolv_backup_path], check=True)
                    cmd = f'echo "nameserver 1.1.1.1\n$(cat {resolv_backup_path})" | sudo tee {resolv_path}'
                    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL)
                    safe_print(f"{GREEN}{T('dns_temp')}{NC}")
                    time.sleep(1)

                    for service in ["ifconfig.me", "icanhazip.com", "ipinfo.io/ip"]:
                        res = subprocess.run(["curl", "-s", "--max-time", str(CURL_TIMEOUT), service], capture_output=True, text=True)
                        if res.returncode == 0 and is_valid_ip(res.stdout.strip()) and res.stdout.strip() != initial_ip:
                            new_ip, ip_verified, dns_fallback_used = res.stdout.strip(), True, True
                            break
            except Exception as e: safe_print(f"{RED}Error: {e}{NC}")
            finally:
                if os.path.exists(resolv_backup_path):
                    try:
                        subprocess.run(["sudo", "mv", resolv_backup_path, resolv_path], check=True)
                        safe_print(f"{BLUE}{T('dns_restored')}{NC}")
                    except Exception: safe_print(f"{RED}Error restoring {resolv_path}.{NC}")

            if dns_fallback_used:
                safe_print(f"{GREEN}{T('dns_success')}{NC}")
            else:
                safe_print(f"{YELLOW}{T('ip_fail_banner')}{NC}")
                time.sleep(3)
                display_failure_banner(T("fail_msg_ip"))
                cleanup(is_failure=is_reconnecting)
                return None, False, None

        safe_print(f"\n{BLUE}{T('get_port')}{NC}")
        internal_ip = get_vpn_internal_ip()
        forwarded_port = get_forwarded_port(internal_ip)

        if forwarded_port and forwarded_port.isdigit():
            try:
                port_file_path = os.path.join(script_dir, PORT_FILE)
                with open(port_file_path, 'w') as f:
                    f.write(str(forwarded_port))
                safe_print(f"{GREEN}{T('port_saved', forwarded_port, PORT_FILE)}{NC}")
            except Exception as e:
                safe_print(f"{RED}Warning: {e}{NC}")

        if ORIGINAL_DEFAULT_ROUTE_DETAILS:
            safe_print(f"{BLUE}{T('del_orig_route')}{NC}")
            safe_print(f"{YELLOW}    default {ORIGINAL_DEFAULT_ROUTE_DETAILS}{NC}")
            subprocess.run(["sudo", "ip", "route", "del", "default"], check=False, capture_output=True)
        
        if not check_and_set_default_route():
            safe_print(f"{YELLOW}Fail route.{NC}")
            time.sleep(3)
            display_failure_banner(T("fail_msg_route"))
            cleanup(is_failure=True)
            return None, False, None

        return new_ip, dns_fallback_used, forwarded_port
    except KeyboardInterrupt:
        cleanup(is_failure=False)
        safe_print(f"\n{YELLOW}{T('conn_cancel')}{NC}")
        return None, False, None

def check_connection_status(expected_ip):
    if subprocess.run(["pgrep", "-x", "openvpn"], capture_output=True).returncode != 0:
        safe_print(f"{RED}{T('status_disconnected')}{NC}")
        return True

    safe_print(f"{YELLOW}{T('check_conn')}{NC}", dynamic=True)
    try:
        all_routes = subprocess.run(["ip", "route"], capture_output=True, text=True).stdout
        
        is_route_ok = ('0.0.0.0/1' in all_routes and '128.0.0.0/1' in all_routes and 'dev tun' in all_routes) or \
                      ('default dev tun' in all_routes)
        
        if not is_route_ok:
            safe_print(f"{RED}{T('status_route_fail')}{NC}")
            return True
    except Exception as e:
        safe_print(f"{RED}Error: {e}{NC}")
        return True

    current_ip = ""
    for _ in range(3):
        for service in ["ifconfig.me", "icanhazip.com", "ipinfo.io/ip"]:
            res = subprocess.run(["curl", "-s", "--max-time", str(CURL_TIMEOUT), service], capture_output=True, text=True)
            if res.returncode == 0 and is_valid_ip(res.stdout.strip()):
                current_ip = res.stdout.strip()
                if current_ip == expected_ip: return False
        time.sleep(IP_RETRY_DELAY)

    safe_print(f"{RED}{T('status_ip_fail', current_ip or 'unknown')}{NC}")
    return True

def route_guardian():
    global ROUTE_CORRECTION_COUNT, LAST_RECONNECTION_TIME
    
    while not GUARDIAN_STOP_EVENT.is_set():
        try:
            ip_route_output = subprocess.run(["ip", "route"], capture_output=True, text=True, check=True).stdout
            
            for line in ip_route_output.strip().split('\n'):
                if line.startswith('default') and 'dev tun' not in line:
                    
                    offending_route = line.strip()
                    safe_print(f"\n{RED}{T('guardian_leak', offending_route)}{NC}")
                    command = f"sudo ip route del {offending_route}"
                    subprocess.run(command, shell=True, check=False, capture_output=True)
                    
                    ROUTE_CORRECTION_COUNT += 1
                    LAST_RECONNECTION_TIME = time.time()
                    log_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(LAST_RECONNECTION_TIME))
                    try:
                        script_dir = os.path.dirname(os.path.realpath(__file__))
                        log_path = os.path.join(script_dir, RECONNECTION_LOG_FILE)
                        with open(log_path, 'a') as f:
                            f.write(f"Correction: {log_time_str}\n")
                    except Exception as e:
                        safe_print(f"{RED}Log Error: {e}{NC}")
                    
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
            safe_print(f"{BLUE}{T('mon_header')}{NC}")
            safe_print(f"{BLUE}======================================={NC}")

            safe_print(f"  {T('lbl_location')} {RED}{selected_location}{NC}")

            duration_seconds = 0
            if CONNECTION_START_TIME:
                duration_seconds = time.time() - CONNECTION_START_TIME
                total_minutes, _ = divmod(int(duration_seconds), 60)
                hours, minutes = divmod(total_minutes, 60)
                safe_print(f"  {T('lbl_time')} {hours}h {minutes}m")

            safe_print(f"  {T('lbl_ip')} {GREEN}{vpn_ip}{NC}")

            port_color = GREEN if forwarded_port and forwarded_port.isdigit() else YELLOW
            port_display = forwarded_port if forwarded_port else "..."
            safe_print(f"  {T('lbl_port')} {port_color}{port_display}{NC}")

            reconnection_color = RED if reconnection_count > 0 else NC
            safe_print(f"  {T('lbl_reconn')} {reconnection_color}{reconnection_count}{NC}")

            if ROUTE_CORRECTION_COUNT > 0:
                safe_print(f"\n  {BLUE}{T('ana_header')}{NC}")
                
                status_color = NC
                stability_metric = 0
                duration_hours = duration_seconds / 3600
                if duration_hours > 0:
                    stability_metric = ROUTE_CORRECTION_COUNT / duration_hours
                    if stability_metric <= 5: status_color = GREEN
                    elif stability_metric <= 20: status_color = YELLOW
                    else: status_color = RED

                correction_line = f"  {T('lbl_route_corr')} {status_color}{ROUTE_CORRECTION_COUNT}{NC}"
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
                    correction_line += T("last_ago", time_str)
                safe_print(correction_line)

                if duration_seconds > 300:
                    safe_print(f"  {T('lbl_corr_rate')} {status_color}{stability_metric:.2f} /h{NC}")

                if (ROUTE_CORRECTION_COUNT >= 4 and 
                    duration_seconds > ANALYSIS_MIN_DURATION and 
                    (time.time() - last_analysis_time) > ANALYSIS_INTERVAL and
                    stability_metric > 5):
                    try:
                        script_dir = os.path.dirname(os.path.realpath(__file__))
                        log_path = os.path.join(script_dir, RECONNECTION_LOG_FILE)
                        timestamps = []
                        with open(log_path, 'r') as f:
                            for line in f:
                                if line.startswith("Correction:"):
                                    time_str = line.replace("Correction: ", "").strip()
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
                            graph_line = f"  {T('lbl_dist')} {GREEN}[{graph_content}]{NC}"

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
                            next_analysis_time_str = time.strftime('%H:%M', time.localtime(time.time() + ANALYSIS_INTERVAL))
                            next_analysis_info = f" {YELLOW}(Next: {next_analysis_time_str}){NC}"
                            if pattern_percentage > 50:
                                pattern_minutes = median_seconds / 60
                                line1 = f"  {T('lbl_pattern')} {GREEN}{T('ana_pattern_yes', int(pattern_percentage), pattern_minutes)}{NC}{next_analysis_info}"
                                # FIX: Alineación dinámica basada en L_WIDTH + 2 espacios de margen
                                indent = " " * (L_WIDTH + 2)
                                line2 = f"{indent}{GREEN}{T('ana_pattern_router')}{NC}"
                                pattern_analysis_line = f"{line1}\n{line2}"
                            else:
                                pattern_analysis_line = f"  {T('lbl_pattern')} {YELLOW}{T('ana_pattern_no')}{NC}{next_analysis_info}"
                        
                        current_block = ""
                        if graph_line: current_block += f"\n{graph_line}"
                        if pattern_analysis_line: current_block += f"\n{pattern_analysis_line}"
                        analysis_result_block = current_block
                        last_analysis_time = time.time()
                    except Exception:
                        pass
                
                if duration_seconds > ANALYSIS_MIN_DURATION and analysis_result_block and stability_metric > 5:
                    safe_print(analysis_result_block)

            next_check_time = time.time() + MONITOR_INTERVAL
            next_check_str = time.strftime('%H:%M:%S', time.localtime(next_check_time))
            
            cycle_seconds = MONITOR_INTERVAL
            if cycle_seconds < 60:
                cycle_str = f"{cycle_seconds}s"
            else:
                mins, secs = divmod(cycle_seconds, 60)
                cycle_str = f"{mins}m {secs}s"
            
            safe_print(f"\n  {T('lbl_check')} {next_check_str} {YELLOW}({cycle_str}){NC}\n")

            status_message = f"{GREEN}{T('status_ok')}{NC}"

            if check_connection_status(expected_ip=vpn_ip):
                reconnection_count += 1
                safe_print(f"\n{YELLOW}{T('conn_lost_retry')}{NC}")
                
                GUARDIAN_STOP_EVENT.set()
                guardian_thread.join(timeout=2)

                cleanup(is_failure=False)
                time.sleep(3)
                
                new_ip, new_dns_fallback, new_port = establish_connection(selected_file, selected_location, initial_ip, is_reconnecting=True)
                
                if not new_ip:
                    safe_print(f"\n{RED}{T('reconn_fail_kill')}{NC}")
                    time.sleep(5)
                    return
                
                vpn_ip, dns_fallback_used, forwarded_port = new_ip, new_dns_fallback, new_port

                safe_print(f"{BLUE}Resetting counters...{NC}")
                ROUTE_CORRECTION_COUNT = 0
                LAST_RECONNECTION_TIME = None
                last_analysis_time = 0
                analysis_result_block = None

                title = T("notif_reconn_title")
                message = T("notif_reconn_msg", forwarded_port)
                send_critical_notification(title, message)

                display_success_banner(selected_location, initial_ip, vpn_ip, True, reconnection_count)
                safe_print(f"{GREEN}{T('reconn_success')}{NC}")
                
                GUARDIAN_STOP_EVENT.clear()
                guardian_thread = threading.Thread(target=route_guardian, daemon=True)
                guardian_thread.start()
                
                time.sleep(4)
                continue

            safe_print(status_message)
            safe_print(f"\n{YELLOW}{T('ctrl_c_exit')}{NC}")
            time.sleep(MONITOR_INTERVAL)
    except KeyboardInterrupt:
        safe_print(f"\n{YELLOW}Stop signal.{NC}")
        GUARDIAN_STOP_EVENT.set()
        guardian_thread.join(timeout=2)
        
        cleanup(is_failure=False)
        
        ROUTE_CORRECTION_COUNT = 0
        LAST_RECONNECTION_TIME = None
        CONNECTION_START_TIME = None

        safe_print(f"\n{YELLOW}{T('exit_mon')}{NC}")
        time.sleep(5)

def display_failure_banner(reason):
    clear_screen()
    safe_print(f"{RED}======================================={NC}")
    safe_print(f"{RED}          {T('fail_title')}")
    safe_print(f"{RED}======================================={NC}")
    safe_print(f"\n  {reason}")

def display_success_banner(location, initial_ip, new_ip, is_reconnecting=False, count=0):
    w = 16
    clear_screen()
    safe_print(f"{GREEN}======================================={NC}")
    safe_print(f"{GREEN}       {T('succ_title')}")
    safe_print(f"{GREEN}======================================={NC}")
    safe_print(f"  {T('lbl_location').strip().ljust(w)} {YELLOW}{location}{NC}")
    if is_reconnecting: safe_print(f"  {T('lbl_reconn').strip().ljust(w)} {YELLOW}{count}{NC}")
    safe_print(f"  {T('succ_orig_ip').strip().ljust(w)} {YELLOW}{initial_ip}{NC}")
    safe_print(f"  {T('succ_vpn_ip').strip().ljust(w)} {GREEN}{new_ip}{NC}\n")

    safe_print(f"  {BLUE}{T('legend_title')}{NC}")
    safe_print(f"  {GREEN}{T('legend_1')}{NC}")
    safe_print(f"  {YELLOW}{T('legend_2')}{NC}")
    safe_print(f"  {RED}{T('legend_3')}{NC}")

def get_user_choice(locations, last_choice=None):
    safe_print(f"{BLUE}{T('menu_avail')}{NC}")
    num_locations = len(locations)
    if num_locations == 0:
        safe_print(f"{RED}{T('menu_none')}{NC}")
    else:
        try:
            terminal_width = os.get_terminal_size().columns
        except OSError:
            terminal_width = 80

        max_digits = len(str(num_locations))
        max_item_width = 0
        for i, location in enumerate(locations):
            item_length = len(f"  {i + 1:>{max_digits}}) {location}")
            if item_length > max_item_width:
                max_item_width = item_length
        
        column_spacing = 4
        single_col_total_width = max_item_width + column_spacing
        num_columns = terminal_width // single_col_total_width
        if num_columns == 0: num_columns = 1
        num_rows = (num_locations + num_columns - 1) // num_columns

        for i in range(num_rows):
            line_parts = []
            for j in range(num_columns):
                index = i + j * num_rows
                if index < num_locations:
                    num = index + 1
                    num_str = f"{num:>{max_digits}}"
                    part_uncolored = f"  {num_str}) {locations[index]}"
                    
                    if last_choice is not None and num == last_choice:
                        part_colored = f"{YELLOW}{part_uncolored}{NC}"
                        if j < num_columns - 1:
                            padding_needed = single_col_total_width - len(part_uncolored)
                            line_parts.append(part_colored + (' ' * padding_needed))
                        else:
                            line_parts.append(part_colored)
                    else:
                        if j < num_columns - 1:
                            line_parts.append(f"{part_uncolored:<{single_col_total_width}}")
                        else:
                            line_parts.append(part_uncolored)
            
            safe_print("".join(line_parts))

    safe_print("")
    safe_print(f"{RED}{T('ctrl_c_exit')}{NC}")

    if last_choice is not None:
        try:
            default_name = locations[last_choice - 1]
            prompt = T("menu_prompt", len(locations), YELLOW + default_name + NC)
        except IndexError:
            last_choice = None
            prompt = T("menu_prompt_no_def", len(locations))
    else:
        prompt = T("menu_prompt_no_def", len(locations))
    
    while True:
        try:
            choice_str = input(prompt)
            
            if choice_str.lower() == 'm':
                return 'MENU'

            if not choice_str and last_choice is not None:
                return last_choice
            
            choice = int(choice_str)
            if 1 <= choice <= len(locations):
                return choice
            safe_print(f"{RED}Error.{NC}")
        except ValueError:
            safe_print(f"{RED}Error.{NC}")
        except KeyboardInterrupt:
            GUARDIAN_STOP_EVENT.set()
            cleanup(is_failure=False)
            safe_print(f"\n{YELLOW}{T('final_exit')}{NC}")
            time.sleep(5)
            sys.exit(0)

def configure_display_screen(config_mgr, script_dir):
    clear_screen()
    safe_print(f"{BLUE}======================================={NC}")
    safe_print(f"{BLUE}    {T('menu_opt_display')}")
    safe_print(f"{BLUE}======================================={NC}")

    ovpn_files = sorted([f for f in os.listdir(script_dir) if f.endswith(".ovpn")])
    if not ovpn_files:
        safe_print(f"{RED}{T('cfg_err_empty')}{NC}")
        time.sleep(2)
        return

    sample_file = ovpn_files[0]
    base_sample = sample_file.replace('.ovpn', '')
    safe_print(f"{YELLOW}{T('cfg_sample')}{NC}{base_sample}\n")

    safe_print(T('cfg_fmt_q'))
    safe_print(T('cfg_fmt_a'))
    safe_print(T('cfg_fmt_b'))
    
    while True:
        fmt = input("> ").upper()
        if fmt in ['A', 'B']: break
    
    sep = input(T('cfg_sep_q'))
    if not sep: sep = "-"

    parts = base_sample.split(sep)
    safe_print(f"\n{BLUE}{T('cfg_parts')}{NC}")
    for i, p in enumerate(parts):
        safe_print(f"  {i}: {p}")
    
    while True:
        try:
            city_idx = int(input(f"\n{T('cfg_idx_city')}"))
            if 0 <= city_idx < len(parts): break
            safe_print(f"{RED}{T('cfg_err_idx')}{NC}")
        except ValueError: pass

    country_idx = None
    if fmt == 'A':
        while True:
            try:
                country_idx = int(input(f"{T('cfg_idx_country')}"))
                if 0 <= country_idx < len(parts): break
                safe_print(f"{RED}{T('cfg_err_idx')}{NC}")
            except ValueError: pass

    config_mgr.update_display_config(fmt, sep, city_idx, country_idx)
    safe_print(f"\n{GREEN}{T('cfg_saved')}{NC}")
    time.sleep(1)

def configure_credentials_screen(config_mgr):
    clear_screen()
    safe_print(f"{BLUE}======================================={NC}")
    safe_print(f"{BLUE}    {T('cfg_creds_title')}")
    safe_print(f"{BLUE}======================================={NC}")
    
    safe_print(f"{YELLOW}{T('cfg_creds_info')}{NC}\n")
    
    try:
        user = input(T('cfg_user')).strip()
        password = getpass.getpass(T('cfg_pass')).strip()
        
        if user and password:
            config_mgr.set_credentials(user, password)
            safe_print(f"\n{GREEN}{T('cfg_creds_saved')}{NC}")
        else:
            safe_print(f"\n{RED}{T('cfg_creds_err')}{NC}")
    except Exception as e:
        safe_print(f"\n{RED}Error: {e}{NC}")
    
    time.sleep(2)

def select_language_screen(config_mgr):
    global CURRENT_LANG
    clear_screen()
    safe_print(f"{BLUE}======================================={NC}")
    safe_print(f"{BLUE}    {T('select_lang')}")
    safe_print(f"{BLUE}======================================={NC}")
    safe_print("  1) Español")
    safe_print("  2) English")
    while True:
        try:
            sel = input("\n> ")
            if sel == "1":
                CURRENT_LANG = "es"
                break
            elif sel == "2":
                CURRENT_LANG = "en"
                break
        except KeyboardInterrupt:
            sys.exit(0)
    config_mgr.set_language(CURRENT_LANG)
    safe_print(f"{GREEN}{T('lang_saved', CURRENT_LANG)}{NC}")
    time.sleep(1)

def main_menu_screen(config_mgr, script_dir):
    while True:
        clear_screen()
        safe_print(f"{BLUE}======================================={NC}")
        safe_print(f"{BLUE}    {T('menu_config_title')}")
        safe_print(f"{BLUE}======================================={NC}")
        safe_print(f"  1) {T('menu_opt_display')}")
        safe_print(f"  2) {T('menu_opt_lang')}")
        safe_print(f"  3) {T('menu_opt_creds')}")
        safe_print(f"  4) {T('menu_opt_back')}")
        
        try:
            sel = input("\n> ")
            if sel == "1":
                configure_display_screen(config_mgr, script_dir)
            elif sel == "2":
                select_language_screen(config_mgr)
            elif sel == "3":
                configure_credentials_screen(config_mgr)
            elif sel == "4":
                break
        except KeyboardInterrupt:
            break

def main():
    global ORIGINAL_RESOLV_CONF_BACKUP, CURRENT_LANG
    
    # --- CONFIGURACIÓN INICIAL ---
    script_dir = os.path.dirname(os.path.realpath(__file__))
    config_mgr = ConfigManager(script_dir)
    
    # Carga inicial de idioma
    saved_lang = config_mgr.get_language()
    if saved_lang:
        CURRENT_LANG = saved_lang
    else:
        select_language_screen(config_mgr)

    if not all(which(cmd) for cmd in ["openvpn", "curl", "sudo", "stty", "nmcli", "ip"]):
        safe_print(f"{RED}{T('error_lib', 'openvpn/curl/sudo/stty/nmcli/ip')}{NC}")
        sys.exit(1)

    clear_screen()
    # --- PANTALLA DE BIENVENIDA Y GUÍA RÁPIDA ---
    safe_print(f"{BLUE}====================================================={NC}")
    safe_print(f"{BLUE}      {T('welcome_title')}      {NC}")
    safe_print(f"{BLUE}====================================================={NC}")
    
    safe_print(f"\n{YELLOW}{T('guide_title')}{NC}")
    
    safe_print(f"\n{GREEN}{T('guide_1')}{NC}")
    safe_print(f"{GREEN}{T('guide_2')}{NC}")
    safe_print(f"{GREEN}{T('guide_3')}{NC}")
    safe_print(f"{GREEN}{T('guide_4')}{NC}")

    # --- JUSTIFICACIÓN DE SUDO ---
    safe_print(f"\n{RED}--------------------------------------------------------------------{NC}")
    safe_print(f"{RED}{T('sudo_simple')}{NC}")
    safe_print(f"{RED}--------------------------------------------------------------------{NC}\n")
    if subprocess.run(["sudo", "-v"], capture_output=True).returncode != 0:
        safe_print(f"{RED}{T('sudo_error')}{NC}")
        sys.exit(1)
    
    threading.Thread(target=keep_sudo_alive, daemon=True).start()

    try:
        if os.path.exists("/etc/resolv.conf"):
            subprocess.run(["sudo", "cp", "/etc/resolv.conf", ORIGINAL_RESOLV_CONF_BACKUP], check=True)
    except Exception as e:
        safe_print(f"{YELLOW}Warning: DNS backup failed: {e}{NC}")

    safe_print(f"{BLUE}{T('check_conn')}{NC}")
    initial_ip = None
    try:
        res = subprocess.run(["curl", "-s", "--max-time", str(CURL_TIMEOUT), "ifconfig.me"], capture_output=True, text=True, check=True)
        ip_candidate = res.stdout.strip()
        if not is_valid_ip(ip_candidate):
            raise ValueError("Invalid IP")
        initial_ip = ip_candidate
        safe_print(f"{GREEN}{T('conn_confirmed')}{NC}")
    except Exception:
        safe_print(f"{YELLOW}{T('repair_attempt')}{NC}")
        
        try:
            safe_print(T('repair_restoring'))
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

            safe_print(T('repair_reset'))
            subprocess.run(["sudo", "nmcli", "networking", "off"], check=True, capture_output=True)
            time.sleep(10)
            subprocess.run(["sudo", "nmcli", "networking", "on"], check=True, capture_output=True)
            time.sleep(15)

            safe_print(T('repair_verify'))
            res = subprocess.run(["curl", "-s", "--max-time", str(CURL_TIMEOUT), "ifconfig.me"], capture_output=True, text=True, check=True)
            ip_candidate = res.stdout.strip()
            if not is_valid_ip(ip_candidate):
                 raise ValueError("Invalid IP after repair")
            initial_ip = ip_candidate
            safe_print(f"{GREEN}{T('repair_success')}{NC}")
            time.sleep(4)
        except Exception as e:
            safe_print(f"\r\033[K{RED}{T('repair_fail')}{NC}")
            safe_print(f"{YELLOW}{T('repair_fail_ext')}{NC}")
            safe_print(f"Error: {e}")
            cleanup(is_failure=False)
            safe_print(f"\n{YELLOW}{T('closing')}{NC}")
            time.sleep(15)
            sys.exit(1)

    # --- VERIFICACIÓN DE CREDENCIALES AL INICIO ---
    vpn_user, vpn_pass = config_mgr.get_credentials()
    if not vpn_user or not vpn_pass:
        safe_print(f"\n{YELLOW}No se detectaron credenciales guardadas.{NC}")
        configure_credentials_screen(config_mgr)

    while True:
        try:
            ovpn_files = sorted([f for f in os.listdir(script_dir) if f.endswith(".ovpn")])
            if not ovpn_files: raise FileNotFoundError(T("err_no_ovpn"))
            locations = [parse_location_name(f, config_mgr.config) for f in ovpn_files]
        except Exception as e:
            safe_print(f"{RED}Error: {e}{NC}")
            sys.exit(1)

        clear_screen()
        safe_print(f"{BLUE}======================================={NC}")
        safe_print(f"{BLUE}    {T('menu_main_title')}")
        safe_print(f"{BLUE}======================================={NC}")
        safe_print(f"\n{T('succ_orig_ip')} {YELLOW}{initial_ip}{NC}\n")
        
        last_choice = config_mgr.get_last_choice()
        if last_choice and (last_choice < 1 or last_choice > len(locations)):
            last_choice = None

        choice = get_user_choice(locations, last_choice)
        
        if choice == 'MENU':
            main_menu_screen(config_mgr, script_dir)
            continue

        config_mgr.set_last_choice(choice)

        selected_file, selected_location = ovpn_files[choice - 1], locations[choice - 1]

        new_ip, dns_fallback_used, forwarded_port = establish_connection(selected_file, selected_location, initial_ip)
        
        if new_ip:
            safe_print(f"{GREEN}OK. 10s...{NC}")
            time.sleep(10)

            display_success_banner(selected_location, initial_ip, new_ip)
            time.sleep(12)
            monitor_connection(selected_file, selected_location, initial_ip, new_ip, dns_fallback_used, forwarded_port)
        else:
            safe_print(f"\n{YELLOW}Menu 5s...{NC}")
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
                    safe_print(f"{RED}{T('term_error')}: {e}{NC}")
        safe_print(f"{RED}{T('term_error')}{NC}")
        safe_print(f"{YELLOW}{T('term_run', script_path)}{NC}")
        sys.exit(1)
    else:
        try:
            main()
        except KeyboardInterrupt:
            GUARDIAN_STOP_EVENT.set()
            cleanup(is_failure=False)
            safe_print(f"\n{YELLOW}{T('final_exit')}{NC}")
            time.sleep(5)
        except Exception as e:
            GUARDIAN_STOP_EVENT.set()
            cleanup(is_failure=True)
            safe_print(f"\n{RED}Error: {e}{NC}")
            time.sleep(5)
            sys.exit(1)
