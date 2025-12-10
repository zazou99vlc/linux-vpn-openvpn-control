#!/usr/bin/env python3
import os
import subprocess
import time
import sys
import threading
import re
import json
import getpass
import itertools
import errno
from shutil import which
from datetime import datetime

# --- VERSIÓN DEL SCRIPT ---
VERSION = "204"

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
PINK = "\033[1;35m"
NC = "\033[0m"

LOG_FILE = "openvpn.log"
PORT_FILE = "forwarded_port.txt"
CONFIG_FILE = "config.json" 
DNS_BACKUP_FILE = "convpn_dns_backup.json"
DNS_LOG_FILE = "convpn_dns.log"
RECONNECTION_LOG_FILE = "reconnections.log"
LOCK_FILE = "convpn.lock"

CONNECTION_TIMEOUT = 20
MONITOR_INTERVAL = 45
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
GUARDIAN_STOP_EVENT = threading.Event()
CONNECTION_START_TIME = None
LAST_RECONNECTION_TIME = None
CURRENT_LANG = "es" 

# --- ESTADO DEL SISTEMA (STATE FLAGS) ---
STATE = {
    "NM_MODIFIED": False,      # ¿Se modificó el perfil .nmconnection?
    "VPN_STARTED": False,      # ¿Se lanzó el proceso OpenVPN?
    "FIREWALL_ACTIVE": False,  # ¿Hay reglas iptables puestas?
    "DNS_APPLIED": False,      # ¿Se cambiaron DNS (NM o resolvectl)?
    "BACKUP_CREATED": False    # ¿Existe el JSON de backup?
}

# --- DICCIONARIO DE IDIOMAS ---
L_WIDTH = 22 

TRANSLATIONS = {
    "es": {
        "closing": "El script se cerrará en 10 segundos...",
        "dns_abort": "Error Crítico: No se detectaron DNS en el log. Abortando conexión por seguridad.",
        "sudo_simple": "Se solicitará acceso de administrador (sudo) para ejecutar\nOpenVPN, firewall y gestionar la red.",
        "ks_active": "Activando Kill Switch (Bloqueo estricto)...",
        "ks_lan": "  > Excepción LAN: {}",
        "ks_vpn": "  > Excepción VPN: {}:{} ({})",
        "ks_tun": "  > Tráfico permitido en túnel: {}",
        "ks_off": "Desactivando Kill Switch...",
        "sudo_error": "Error: No se pudo obtener privilegios de sudo.",
        "term_error": "No se detectó un terminal compatible.",
        "term_run": "Ejecuta: python3 '{}' --run-in-terminal",
        "ctrl_c_exit": "Ctrl+C -> Salir",
        "final_exit": "Saliendo en 5 segundos...",
        "clean_start": "Iniciando secuencia de limpieza...",
        "clean_skip_net": "  > No se detectaron cambios pendientes en el registro.",
        "clean_vpn_stop": "  > Deteniendo proceso OpenVPN...",
        "clean_dns_rev": "  > Revirtiendo cambios de DNS (resolvectl)...",
        "clean_nm_rest": "  > Restaurando perfil NetworkManager '{}'...",
        "clean_files": "  > Borrando archivos temporales y bloqueo...",
        "clean_kill_skip": "  > VPN no iniciada: No se requiere Corte de Emergencia.",
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
        "check_ping": "Verificando conectividad (ping 8.8.8.8)...",
        "ping_ok": "Verificando conectividad (ping 8.8.8.8)... OK.",
        "ping_fail": "Verificando conectividad (ping 8.8.8.8)... FALLO.",
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
        "lbl_guardian_freq": "Frecuencia Guardián:".ljust(L_WIDTH),
        "lbl_route_corr": "Correcciones Ruta:".ljust(L_WIDTH),
        "lbl_corr_rate": "Tasa Corrección:".ljust(L_WIDTH),
        "lbl_dist": "Distribución:".ljust(L_WIDTH),
        "lbl_pattern": "Análisis Patrón:".ljust(L_WIDTH),
        "lbl_check": "Comprobación:".ljust(L_WIDTH),
        "ana_header": "--- Análisis de Estabilidad de Ruta ---",
        "ana_pattern_yes": "{}% correcciones con patrón ~{:.1f} min.",
        "ana_pattern_router": " (Posiblemente DHCP del router)",
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
        "menu_opt_post": "Configurar Script Post-Conexión",
        "menu_opt_launcher": "Crear Lanzador de Escritorio",
        "menu_opt_back": "Volver (Enter)",
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
        "err_no_creds": "Error: No hay credenciales configuradas.",
        "dns_extract_fail": "No se encontraron DNS. Usando Fallback (8.8.8.8).",
        "dns_prompt_opt": "1) Reintentar  2) Abortar: ",
        "dns_apply_success": "DNS aplicadas vía NetworkManager a {}: {}",
        "dns_apply_fail": "Fallo al aplicar DNS vía NM.",
        "nm_reload_prompt": "¿Recargar NetworkManager? (s/n): ",
        "dns_backup_ok": "Backup de DNS guardado en JSON.",
        "dns_restore_ok": "DNS restauradas desde backup JSON.",
        "arch_detect": "Sistema con systemd-resolved detectado (Arch mode).",
        "arch_apply": "Aplicando DNS nativas (resolvectl) y dominio '~.' a {}",
        "launcher_created": "Lanzador creado en: {}",
        "launcher_error": "Error creando lanzador: {}",
        "cfg_post_title": "Configurar Script Post-Conexión",
        "cfg_post_info": "Este script se ejecutará automáticamente tras conectar la VPN.\nDeja en blanco para desactivar.",
        "cfg_post_warn_spaces": "AVISO: Se corregirán comillas y espacios automáticamente.\nPuedes usar nombre de archivo local.",
        "cfg_post_current": "Configuración actual: ",
        "cfg_post_none": "Desactivado",
        "cfg_post_prompt": "Ruta o Nombre (Intro=Mantener, D=Desactivar): ",
        "cfg_post_kept": "Configuración mantenida.",
        "cfg_post_saved": "Script configurado: {}",
        "cfg_post_removed": "Script post-conexión desactivado.",
        "cfg_post_err": "El archivo no existe o no es ejecutable.",
        "ks_fallback_error": "ERROR: No se pudo establecer Kill Switch estricto",
        "ks_no_server_ip": "No se pudo obtener IP/Puerto del servidor VPN",
        "ks_traffic_leak_warning": "Tu tráfico podría filtrarse si cae la VPN",
        "ks_abort_connection": "Abortando conexión por seguridad",
        "menu_opt_doh": "Bloquear DoH (Anti-Fugas)",
        "cfg_doh_title": "Configurar Bloqueo DoH",
        "cfg_doh_info": "Bloquea IPs de Cloudflare/Google/Quad9 (HTTPS) para forzar\nel uso de DNS de la VPN y evitar fugas en navegadores.",
        "cfg_doh_status": "Estado actual: ",
        "cfg_doh_on": "ACTIVADO (Bloqueo estricto)",
        "cfg_doh_off": "DESACTIVADO",
        "cfg_doh_prompt": "¿Cambiar estado? (s/n): ",
        "cfg_doh_saved": "Configuración DoH guardada: {}",
        "ks_doh": "  > Bloqueando DoH (Anti-Fugas): {}",
        "clean_doh": "  > Eliminando reglas de bloqueo DoH...",
        "menu_opt_lan": "Bloquear LAN (Modo Paranoia)",
        "cfg_lan_title": "Configurar Bloqueo de LAN",
        "cfg_lan_info": "Impide la comunicación con equipos locales (Impresoras, NAS).\nRecomendado en redes públicas (Hoteles, Aeropuertos).",
        "cfg_lan_status": "Estado actual: ",
        "cfg_lan_on": "ACTIVADO (Aislamiento Total)",
        "cfg_lan_off": "DESACTIVADO (Permitir LAN)",
        "cfg_lan_prompt": "¿Cambiar estado? (s/n): ",
        "cfg_lan_saved": "Configuración LAN guardada: {}",
        "ks_lan_block": "  > LAN BLOQUEADA (Modo Paranoia activo).",
        "exec_post": "Ejecutando script post-conexión (Usuario: {})..."
    },
    "en": {
        "closing": "Script will close in 10 seconds...",
        "dns_abort": "Critical Error: No DNS detected in log. Aborting connection for security.",
        "sudo_simple": "Administrator access (sudo) will be requested to run\nOpenVPN, firewall and manage the network.",
        "sudo_error": "Error: Could not get sudo privileges.",
        "term_error": "No compatible terminal found.",
        "term_run": "Run: python3 '{}' --run-in-terminal",
        "ctrl_c_exit": "Ctrl+C -> Exit",
        "ks_active": "Activating Kill Switch (Strict Block)...",
        "ks_lan": "  > LAN Exception: {}",
        "ks_vpn": "  > VPN Exception: {}:{} ({})",
        "ks_tun": "  > Tunnel traffic allowed: {}",
        "ks_off": "Deactivating Kill Switch...",
        "final_exit": "Exiting in 5 seconds...",
        "clean_start": "Starting cleanup sequence...",
        "clean_skip_net": "  > No pending network changes detected.",
        "clean_vpn_stop": "  > Stopping OpenVPN process...",
        "clean_dns_rev": "  > Reverting DNS changes (resolvectl)...",
        "clean_nm_rest": "  > Restoring NetworkManager profile '{}'...",
        "clean_files": "  > Deleting temporary files and lock...",
        "clean_kill_skip": "  > VPN not started: Emergency Cut not required.",
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
        "check_ping": "Verifying connectivity (ping 8.8.8.8)...",
        "ping_ok": "Verifying connectivity (ping 8.8.8.8)... OK.",
        "ping_fail": "Verifying connectivity (ping 8.8.8.8)... FAILED.",
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
        "lbl_guardian_freq": "Guardian Frequency:".ljust(L_WIDTH),
        "lbl_route_corr": "Route Corrections:".ljust(L_WIDTH),
        "lbl_corr_rate": "Correction Rate:".ljust(L_WIDTH),
        "lbl_dist": "Distribution:".ljust(L_WIDTH),
        "lbl_pattern": "Pattern Analysis:".ljust(L_WIDTH),
        "lbl_check": "Next Check:".ljust(L_WIDTH),
        "ana_header": "--- Route Stability Analysis ---",
        "ana_pattern_yes": "{}% corrections with pattern ~{:.1f} min.",
        "ana_pattern_router": " (Possibly router DHCP)",
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
        "menu_opt_post": "Configure Post-Connection Script",
        "menu_opt_launcher": "Create Desktop Launcher",
        "menu_opt_back": "Back (Enter)",
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
        "err_no_creds": "Error: No credentials configured.",
        "dns_extract_fail": "No DNS found. Using Fallback (8.8.8.8).",
        "dns_prompt_opt": "1) Retry  2) Abort: ",
        "dns_apply_success": "DNS applied via NetworkManager to {}: {}",
        "dns_apply_fail": "Failed to apply DNS via NM.",
        "nm_reload_prompt": "Reload NetworkManager? (y/n): ",
        "dns_backup_ok": "DNS backup saved to JSON.",
        "dns_restore_ok": "DNS restored from JSON backup.",
        "arch_detect": "Systemd-resolved detected (Arch mode).",
        "arch_apply": "Applying native DNS (resolvectl) and domain '~.' to {}",
        "launcher_created": "Launcher created at: {}",
        "launcher_error": "Error creating launcher: {}",
        "cfg_post_title": "Configure Post-Connection Script",
        "cfg_post_info": "This script will run automatically after VPN connection.\nLeave blank to disable.",
        "cfg_post_warn_spaces": "WARNING: Quotes and spaces will be auto-corrected.\nYou can use local filename.",
        "cfg_post_current": "Current setting: ",
        "cfg_post_none": "Disabled",
        "cfg_post_prompt": "Path or Name (Enter=Keep, D=Disable): ",
        "cfg_post_kept": "Configuration kept.",
        "cfg_post_saved": "Script configured: {}",
        "cfg_post_removed": "Post-connection script disabled.",
        "cfg_post_err": "File does not exist or is not executable.",
        "ks_fallback_error": "ERROR: Could not establish strict Kill Switch",
        "ks_no_server_ip": "Could not obtain VPN server IP/Port",
        "ks_traffic_leak_warning": "Your traffic could leak if VPN drops",
        "ks_abort_connection": "Aborting connection for security",
"menu_opt_doh": "Block DoH (Anti-Leak)",
        "cfg_doh_title": "Configure DoH Blocking",
        "cfg_doh_info": "Blocks Cloudflare/Google/Quad9 IPs (HTTPS) to force\nVPN DNS usage and prevent browser leaks.",
        "cfg_doh_status": "Current status: ",
        "cfg_doh_on": "ENABLED (Strict Block)",
        "cfg_doh_off": "DISABLED",
        "cfg_doh_prompt": "Change status? (y/n): ",
        "cfg_doh_saved": "DoH setting saved: {}",
        "ks_doh": "  > Blocking DoH (Anti-Leak): {}",
        "clean_doh": "  > Removing DoH rules...",
        "menu_opt_lan": "Block LAN (Paranoia Mode)",
        "cfg_lan_title": "Configure LAN Blocking",
        "cfg_lan_info": "Prevents communication with local devices (Printers, NAS).\nRecommended for public networks (Hotels, Airports).",
        "cfg_lan_status": "Current status: ",
        "cfg_lan_on": "ENABLED (Total Isolation)",
        "cfg_lan_off": "DISABLED (Allow LAN)",
        "cfg_lan_prompt": "Change status? (y/n): ",
        "cfg_lan_saved": "LAN setting saved: {}",
        "ks_lan_block": "  > LAN BLOCKED (Paranoia Mode active).",
        "exec_post": "Executing post-connection script (User: {})..."
    }
}

# --- GESTIÓN DE CONFIGURACIÓN E IDIOMA ---
class ConfigManager:
    def __init__(self, script_dir):
        self.config_path = os.path.join(script_dir, CONFIG_FILE)
        self.machine_key = self.get_machine_key()
        self.config = self.load_config()

    def get_machine_key(self):
        """Obtiene una clave única basada en el hardware (Machine ID)."""
        try:
            if os.path.exists("/etc/machine-id"):
                with open("/etc/machine-id", "r") as f:
                    return f.read().strip()
            elif os.path.exists("/var/lib/dbus/machine-id"):
                with open("/var/lib/dbus/machine-id", "r") as f:
                    return f.read().strip()
        except Exception:
            pass
        import uuid
        return str(uuid.getnode())

    def xor_cipher(self, text, key):
        return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(text, itertools.cycle(key)))

    def encrypt(self, plaintext):
        if not plaintext: return None
        try:
            xor_result = self.xor_cipher(plaintext, self.machine_key)
            return xor_result.encode('utf-8').hex()
        except Exception:
            return None

    def decrypt(self, hex_text):
        if not hex_text: return None
        try:
            xor_text = bytes.fromhex(hex_text).decode('utf-8')
            return self.xor_cipher(xor_text, self.machine_key)
        except Exception:
            return None

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
        self.config["vpn_user_enc"] = self.encrypt(user)
        self.config["vpn_pass_enc"] = self.encrypt(password)
        if "vpn_user" in self.config: del self.config["vpn_user"]
        if "vpn_pass" in self.config: del self.config["vpn_pass"]
        self.save_config()
        os.chmod(self.config_path, 0o600)

    def get_credentials(self):
        u_enc = self.config.get("vpn_user_enc")
        p_enc = self.config.get("vpn_pass_enc")
        if u_enc and p_enc:
            return self.decrypt(u_enc), self.decrypt(p_enc)
        return None, None
    
    def set_post_script(self, path):
        self.config["post_script"] = path
        self.save_config()

    def get_post_script(self):
        return self.config.get("post_script")
        
    def set_doh_blocking(self, enabled):
        self.config["block_doh"] = enabled
        self.save_config()

    def get_doh_blocking(self):
        return self.config.get("block_doh", False)
        
    def set_lan_blocking(self, enabled):
        self.config["block_lan"] = enabled
        self.save_config()

    def get_lan_blocking(self):
        return self.config.get("block_lan", False)     

def T(key, *args):
    lang_dict = TRANSLATIONS.get(CURRENT_LANG, TRANSLATIONS["es"])
    text = lang_dict.get(key, key)
    if args:
        try:
            return text.format(*args)
        except IndexError:
            return text
    return text

# --- GESTIÓN DE LOCKFILE INTELIGENTE (JOURNALING) ---
def get_lock_state():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    lock_path = os.path.join(script_dir, LOCK_FILE)
    if os.path.exists(lock_path):
        try:
            with open(lock_path, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return None

def create_lock_file():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    lock_path = os.path.join(script_dir, LOCK_FILE)
    initial_state = {
        "pid": os.getpid(),
        "actions": {}
    }
    try:
        with open(lock_path, 'w') as f:
            json.dump(initial_state, f)
    except Exception:
        pass

def update_lock_state(key, value):
    script_dir = os.path.dirname(os.path.realpath(__file__))
    lock_path = os.path.join(script_dir, LOCK_FILE)
    try:
        state = {}
        if os.path.exists(lock_path):
            with open(lock_path, 'r') as f:
                state = json.load(f)
        
        if "actions" not in state: state["actions"] = {}
        state["actions"][key] = value
        
        with open(lock_path, 'w') as f:
            json.dump(state, f)
    except Exception:
        pass

# --- FUNCIONES DE RED, DNS Y FIREWALL ---

def log_dns_action(script_dir, action, data):
    log_path = os.path.join(script_dir, DNS_LOG_FILE)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(log_path, "a") as f:
            f.write(f"[{timestamp}] {action}: {data}\n")
    except Exception:
        pass

def detect_main_iface_nm():
    try:
        nmcli_output = subprocess.run(
            ["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"],
            capture_output=True, text=True, check=True
        ).stdout
        for line in nmcli_output.strip().split('\n'):
            parts = line.split(':')
            if len(parts) > 1 and parts[1].lower() != 'lo' and not parts[1].lower().startswith('tun'):
                return parts[1] 
    except Exception:
        pass
    return None
    
def get_cached_physical_interface(script_dir):
    state = get_lock_state()
    if state and "actions" in state:
        cached = state["actions"].get("physical_interface")
        if cached: return cached
    iface = detect_main_iface_nm()
    if iface: update_lock_state("physical_interface", iface)
    return iface

def is_systemd_resolved_active():
    try:
        subprocess.run(["resolvectl", "status"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False
#######
def get_local_subnet(interface):
    try:
        # Obtiene la subred local (ej. 192.168.1.0/24) para permitir tráfico LAN
        cmd = ["ip", "-o", "route", "show", "dev", interface, "scope", "link"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        for line in res.stdout.strip().split('\n'):
            if "proto kernel" in line and "src" in line:
                return line.split()[0]
    except Exception: pass
    return None
    
def is_ufw_active():
    # Comprueba si UFW está instalado y activo
    if not which("ufw"): return False
    try:
        res = subprocess.run(["sudo", "ufw", "status"], capture_output=True, text=True)
        return "Status: active" in res.stdout or "Estado: activo" in res.stdout
    except Exception: return False    

def extract_connection_details(script_dir):
    # Extrae IP, Puerto y Protocolo REALES del log de OpenVPN (Flexible)
    log_path = os.path.join(script_dir, LOG_FILE)
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r', errors='ignore') as f:
                content = f.read()
                # Busca: UDPv4 link remote: [AF_INET]217.138.222.67:1194 (Ignorando texto intermedio)
                match = re.search(r"(UDP|TCP).*?remote:.*?(?:\[.*?\])?\s*([0-9.]+):([0-9]+)", content, re.IGNORECASE)
                if match:
                    proto = "udp" if "udp" in match.group(1).lower() else "tcp"
                    return match.group(2), match.group(3), proto
        except Exception: pass
    return None, None, None
#######
  
def manage_kill_switch(phys_iface, tun_iface, action="add", vpn_ip=None, vpn_port=None, proto="udp", script_dir=None, restore_ufw=False, block_doh=False, block_lan=False):
    if not phys_iface: return
    ipt, ip6t = ["sudo", "iptables"], ["sudo", "ip6tables"]
    
    if action == "add":
        # 1. Gestión de UFW (Evitar conflictos)
        if is_ufw_active():
            safe_print(f"{YELLOW}UFW activo detectado. Desactivando temporalmente para Kill Switch...{NC}")
            subprocess.run(["sudo", "ufw", "disable"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if script_dir: update_lock_state("ufw_was_active", True)

        safe_print(f"{YELLOW}{T('ks_active')}{NC}")
        local_subnet = get_local_subnet(phys_iface)
        
        # 2. Limpieza y Políticas DROP
        for cmd in [ipt, ip6t]:
            subprocess.run(cmd + ["-F"], check=False, stderr=subprocess.DEVNULL)
            subprocess.run(cmd + ["-X"], check=False, stderr=subprocess.DEVNULL)
            subprocess.run(cmd + ["-P", "INPUT", "DROP"], check=False, stderr=subprocess.DEVNULL)
            subprocess.run(cmd + ["-P", "FORWARD", "DROP"], check=False, stderr=subprocess.DEVNULL)
            subprocess.run(cmd + ["-P", "OUTPUT", "DROP"], check=False, stderr=subprocess.DEVNULL)

        # 3. Loopback
        subprocess.run(ipt + ["-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(ipt + ["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], check=False, stderr=subprocess.DEVNULL)

        # 4. LAN
        if local_subnet:
            if block_lan:
                safe_print(f"{RED}{T('ks_lan_block')}{NC}")
                # No añadimos reglas ACCEPT, por lo que la política por defecto (DROP) bloqueará la LAN.
            else:
                safe_print(f"{BLUE}{T('ks_lan', local_subnet)}{NC}")
                subprocess.run(ipt + ["-A", "INPUT", "-s", local_subnet, "-j", "ACCEPT"], check=False, stderr=subprocess.DEVNULL)
                subprocess.run(ipt + ["-A", "OUTPUT", "-d", local_subnet, "-j", "ACCEPT"], check=False, stderr=subprocess.DEVNULL)

        # 5. VPN
        if vpn_ip: #and vpn_port:
            safe_print(f"{BLUE}{T('ks_vpn', vpn_ip, 'ANY', 'ALL')}{NC}")
            # Salida permitida
            subprocess.run(ipt + ["-A", "OUTPUT", "-o", phys_iface, "-d", vpn_ip, "-j", "ACCEPT"], check=False, stderr=subprocess.DEVNULL)
            # Entrada permitida
            subprocess.run(ipt + ["-A", "INPUT", "-i", phys_iface, "-s", vpn_ip, "-j", "ACCEPT"], check=False, stderr=subprocess.DEVNULL)

        # 6. Túnel
        if tun_iface:
            safe_print(f"{BLUE}{T('ks_tun', tun_iface)}{NC}")
            subprocess.run(ipt + ["-A", "OUTPUT", "-o", tun_iface, "-j", "ACCEPT"], check=False, stderr=subprocess.DEVNULL)
            subprocess.run(ipt + ["-A", "INPUT", "-i", tun_iface, "-j", "ACCEPT"], check=False, stderr=subprocess.DEVNULL)
        # 7. Bloqueo DoH (Anti-Fugas)
        if block_doh:
            # Cloudflare, Google, Quad9
            doh_ips = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"]
            safe_print(f"{BLUE}{T('ks_doh', 'Cloudflare/Google/Quad9')}{NC}")
            for ip in doh_ips:
                # Insertamos al principio (1) para que tenga prioridad sobre cualquier ACCEPT
                subprocess.run(ipt + ["-I", "OUTPUT", "1", "-d", ip, "-p", "tcp", "--dport", "443", "-j", "DROP"], check=False, stderr=subprocess.DEVNULL)
            
            if script_dir:
                update_lock_state("doh_blocked", True)
        
        if script_dir:
            update_lock_state("kill_switch_active", True)
            update_lock_state("firewall_iface", phys_iface)

    elif action == "del":
        safe_print(f"{BLUE}{T('ks_off')}{NC}")
        for cmd in [ipt, ip6t]:
            subprocess.run(cmd + ["-P", "INPUT", "ACCEPT"], check=False, stderr=subprocess.DEVNULL)
            subprocess.run(cmd + ["-P", "FORWARD", "ACCEPT"], check=False, stderr=subprocess.DEVNULL)
            subprocess.run(cmd + ["-P", "OUTPUT", "ACCEPT"], check=False, stderr=subprocess.DEVNULL)
            subprocess.run(cmd + ["-F"], check=False, stderr=subprocess.DEVNULL)
            subprocess.run(cmd + ["-X"], check=False, stderr=subprocess.DEVNULL)
        
        # Restaurar UFW si estaba activo
        if restore_ufw:
            safe_print(f"{BLUE}Restaurando UFW (Firewall del sistema)...{NC}")
            # --force evita que pida confirmación "y/n"
            subprocess.run(["sudo", "ufw", "--force", "enable"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
def backup_original_dns(script_dir, dns_backup_path):
    backup_data = {"timestamp": datetime.now().isoformat(), "interfaces": {}}
    main_iface = get_cached_physical_interface(script_dir)
    if main_iface:
        try:
            res = subprocess.run(["nmcli", "-g", "IP4.DNS", "device", "show", main_iface], capture_output=True, text=True)
            if res.returncode == 0:
                backup_data["interfaces"][main_iface] = res.stdout.strip().split()
        except Exception:
            pass
    try:
        with open(dns_backup_path, 'w') as f:
            json.dump(backup_data, f)
        log_dns_action(script_dir, "BACKUP", f"Saved to {dns_backup_path}")
        update_lock_state("backup_created", True)
        safe_print(f"{GREEN}{T('dns_backup_ok')}{NC}")
    except Exception as e:
        safe_print(f"{RED}DNS Backup Error: {e}{NC}")

def extract_vpn_dns_from_log(script_dir):
    log_path = os.path.join(script_dir, LOG_FILE)
    dns_servers = []
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r', errors='ignore') as f:
                content = f.read()
                matches = re.findall(r"dhcp-option DNS ([\d\.]+)", content)
                if matches: dns_servers.extend(matches)
                matches_v4 = re.findall(r"net_dns_v4_add:\s+([\d\.]+)", content)
                if matches_v4: dns_servers.extend(matches_v4)
        except Exception:
            pass
    return list(dict.fromkeys(dns_servers))

def detect_tun_interface_from_log(script_dir):
    log_path = os.path.join(script_dir, LOG_FILE)
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r', errors='ignore') as f:
                content = f.read()
                match = re.search(r"TUN/TAP device (tun\d+) opened", content)
                if match: return match.group(1)
        except Exception:
            pass
    return None

def apply_dns_arch_native(tun_iface, dns_list, phys_iface, script_dir):
    safe_print(f"{BLUE}{T('arch_apply', tun_iface)}{NC}")
    final_dns = dns_list
    try:
        subprocess.run(["sudo", "resolvectl", "dns", tun_iface] + final_dns, check=True)
        subprocess.run(["sudo", "resolvectl", "domain", tun_iface, "~."], check=True)
        subprocess.run(["sudo", "resolvectl", "default-route", tun_iface, "yes"], check=True)
        if phys_iface:
             #202#subprocess.run(["sudo", "resolvectl", "dns", phys_iface, ""], check=False, stderr=subprocess.DEVNULL)
             subprocess.run(["sudo", "resolvectl", "flush-caches"], check=False)
        log_dns_action(script_dir, "ARCH_APPLY", f"Interface: {tun_iface}, DNS: {final_dns}")
        return True
    except Exception as e:
        safe_print(f"{RED}Arch DNS Error: {e}{NC}")
        return False

def apply_dns_via_nm(tun_iface, dns_list, script_dir):
    if not tun_iface: return False
    final_dns = dns_list
    dns_str = " ".join(final_dns)
    safe_print(f"{BLUE}Applying DNS to {tun_iface}: {dns_str}{NC}")
    try:
        cmd = ["sudo", "nmcli", "device", "modify", tun_iface, "ipv4.dns", dns_str, "ipv4.ignore-auto-dns", "yes"]
        subprocess.run(cmd, check=True, capture_output=True)
        log_dns_action(script_dir, "APPLY_NM", f"Interface: {tun_iface}, DNS: {dns_str}")
        safe_print(f"{GREEN}{T('dns_apply_success', tun_iface, dns_str)}{NC}")
        return True
    except subprocess.CalledProcessError as e:
        safe_print(f"{RED}{T('dns_apply_fail')}: {e}{NC}")
        return False

def prompt_reload_nm(script_dir):
    try:
        choice = input(f"{YELLOW}{T('nm_reload_prompt')}{NC}")
        if choice.lower().startswith('s') or choice.lower().startswith('y'):
            safe_print(f"{BLUE}Reloading NetworkManager...{NC}")
            subprocess.run(["sudo", "service", "NetworkManager", "restart"], check=True)
            time.sleep(5)
    except Exception:
        pass

def restore_original_dns_from_backup(script_dir, dns_backup_path):
    if not os.path.exists(dns_backup_path): return
    try:
        subprocess.run(["sudo", "rm", "-f", dns_backup_path], check=False, stderr=subprocess.DEVNULL)
        safe_print(f"{GREEN}{T('dns_restore_ok')}{NC}")
    except Exception as e:
        safe_print(f"{RED}Restore Error: {e}{NC}")

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
    script_dir = os.path.dirname(os.path.realpath(__file__))
    log_path = os.path.join(script_dir, LOG_FILE)
    if os.path.exists(log_path):
        try:
            with open(log_path, 'r', errors='ignore') as f:
                content = f.read()
                # 1. Patrón moderno (Linux/DCO)
                match = re.search(r"net_addr_v4_add:\s+([0-9.]+)", content)
                if match: return match.group(1)
                
                # 2. Patrón estándar PUSH_REPLY (ifconfig IP MASCARA)
                match = re.search(r"ifconfig\s+([0-9.]+)\s+[0-9.]+", content)
                if match: return match.group(1)
                
                # 3. Patrón legacy (ip addr add)
                match = re.search(r"ip\s+addr\s+add\s+([0-9.]+)", content)
                if match: return match.group(1)
        except Exception:
            pass
    return None

def get_forwarded_port(internal_ip):
    if not internal_ip: return None
    api_url = f"https://connect.pvdatanet.com/v3/Api/port?ip[]={internal_ip}"
    for attempt in range(1, 4):
        try:
            safe_print(f"{YELLOW}{T('get_port')} ({attempt}/3)...{NC}", dynamic=True)
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(api_url, headers=headers, timeout=API_TIMEOUT)
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
        except Exception:
            if attempt < 3: time.sleep(2)
            else: safe_print(f"{RED}API Error{NC}")
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

def cleanup(is_failure=False, state_override=None):
    global ORIGINAL_DEFAULT_ROUTE_DETAILS
    
    safe_print(f"\n{YELLOW}{T('clean_start')}{NC}")
    subprocess.run(["sudo", "killall", "-q", "openvpn"], check=False, stderr=subprocess.DEVNULL) # <--- MATA EL PROCESO ZOMBIE
    script_dir = os.path.dirname(os.path.realpath(__file__))

    state_data = state_override if state_override is not None else get_lock_state()
    actions = state_data.get("actions", {}) if state_data else {}

    # 1. FIREWALL & KILL SWITCH
    fw_iface = actions.get("firewall_iface")
    ufw_was_active = actions.get("ufw_was_active", False)
    doh_was_blocked = actions.get("doh_blocked", False)

    # Creamos un conjunto con las interfaces (elimina duplicados y nulos automáticamente)
    cached_iface = get_cached_physical_interface(script_dir)
    interfaces_to_clean = {fw_iface, cached_iface} - {None}
    
    for iface in interfaces_to_clean:
        manage_kill_switch(iface, None, action="del", restore_ufw=ufw_was_active)
            
    # 3. DNS & NETWORK
    if actions.get("resolv_locked"):
        safe_print(f"{BLUE}  > Desbloqueando /etc/resolv.conf...{NC}")
        subprocess.run(["sudo", "chattr", "-i", "/etc/resolv.conf"], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "mv", "/etc/resolv.conf.bak", "/etc/resolv.conf"], check=False, stderr=subprocess.DEVNULL)

    nm_conn = actions.get("nm_connection")
    arch_dns = actions.get("arch_dns")
    backup_created = actions.get("backup_created")
    dns_applied = actions.get("dns_applied")

    if nm_conn or arch_dns or backup_created or dns_applied:
        
        # A. Arch Linux / Systemd-resolved
        if is_systemd_resolved_active():
            safe_print(f"{BLUE}{T('clean_dns_rev')}{NC}")
            if fw_iface:
                subprocess.run(["sudo", "resolvectl", "revert", fw_iface], check=False, stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "resolvectl", "flush-caches"], check=False, stderr=subprocess.DEVNULL)

        # B. NetworkManager Restore
        if nm_conn:
            dns_backup_path = os.path.join(script_dir, DNS_BACKUP_FILE)
            restore_original_dns_from_backup(script_dir, dns_backup_path)
            
            safe_print(f"{BLUE}{T('clean_nm_rest', nm_conn)}{NC}")
            try:
                orig_state = actions.get("nm_original_state", {})
                
                val_v4_never = orig_state.get("ipv4.never-default", "no")
                val_v4_ignore = orig_state.get("ipv4.ignore-auto-routes", "no")
                val_v6_method = orig_state.get("ipv6.method", "disabled")

                subprocess.run(["sudo", "nmcli", "connection", "modify", nm_conn, "ipv4.never-default", val_v4_never], check=True, capture_output=True)
                subprocess.run(["sudo", "nmcli", "connection", "modify", nm_conn, "ipv4.ignore-auto-routes", val_v4_ignore], check=True, capture_output=True)
                subprocess.run(["sudo", "nmcli", "connection", "modify", nm_conn, "ipv6.method", val_v6_method], check=False, capture_output=True)
                
                subprocess.run(["sudo", "nmcli", "connection", "up", nm_conn], check=True, capture_output=True)
                safe_print(f"{GREEN}{T('nm_success')}{NC}")
            except Exception as e:
                safe_print(f"{YELLOW}{T('nm_crit_error', e)}{NC}")
                safe_print(f"{YELLOW}{T('nm_manual')}{NC}")
    else:
        safe_print(f"{GREEN}{T('clean_skip_net')}{NC}")

    # 4. KILL SWITCH
    if is_failure:
        if actions.get("vpn_started"): 
            safe_print(f"{RED}{T('kill_switch_active')}{NC}")
            subprocess.run(["sudo", "nmcli", "networking", "off"], capture_output=True, text=True)
            send_critical_notification(T("notif_title_crit"), T("notif_msg_kill"))
        else:
            safe_print(f"{YELLOW}{T('clean_kill_skip')}{NC}")

    # 5. ARCHIVOS
    safe_print(f"{BLUE}{T('clean_files')}{NC}")
    for f in [LOG_FILE, PORT_FILE, RECONNECTION_LOG_FILE, DNS_LOG_FILE, DNS_BACKUP_FILE, LOCK_FILE]:
        p = os.path.join(script_dir, f)
        if os.path.exists(p): 
            try: os.remove(p)
            except: subprocess.run(["sudo", "rm", "-f", p], check=False, stderr=subprocess.DEVNULL)

    safe_print(f"\n{GREEN}{T('clean_complete')}{NC}")
    if is_failure and actions.get("vpn_started"): 
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
    global ORIGINAL_DEFAULT_ROUTE_DETAILS, CONNECTION_START_TIME
    try:
        CONNECTION_START_TIME = time.time()
        start_time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(CONNECTION_START_TIME))
        script_dir = os.path.dirname(os.path.realpath(__file__))
        
        try:
            with open(os.path.join(script_dir, RECONNECTION_LOG_FILE), 'w') as f:
                f.write(f"Time: {start_time_str}\n")
        except Exception: pass

        clear_screen()
        msg = T("conn_lost_retry") if is_reconnecting else T("connecting_to", selected_location)
        safe_print(f"{YELLOW}{msg}{NC}\n")
        log_file_path = os.path.join(script_dir, LOG_FILE)

        if not is_reconnecting:
            ORIGINAL_DEFAULT_ROUTE_DETAILS = get_current_default_route_details()
            if ORIGINAL_DEFAULT_ROUTE_DETAILS:
                safe_print(f"{BLUE}{T('orig_route_detect', ORIGINAL_DEFAULT_ROUTE_DETAILS)}{NC}")
            else:
                safe_print(f"{RED}Error: Route?{NC}")
                return None, False, None

        safe_print(f"\n{BLUE}{T('prep_net')}{NC}")
        
        active_connection_name = None
        physical_device = get_cached_physical_interface(script_dir)
        
        try:
            nmcli_output = subprocess.run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"], capture_output=True, text=True, check=True).stdout
            for line in nmcli_output.strip().split('\n'):
                parts = line.split(':')
                if len(parts) > 1 and parts[1].lower() != 'lo' and not parts[1].lower().startswith('tun'):
                    active_connection_name = parts[0]
                    break
            
            if active_connection_name:
                safe_print(f"  > Analizando configuración previa de '{active_connection_name}'...")
                
                def get_nm_prop(prop):
                    try:
                        res = subprocess.run(["nmcli", "-g", prop, "connection", "show", active_connection_name], capture_output=True, text=True)
                        return res.stdout.strip() if res.returncode == 0 else None
                    except: return None

                orig_v4_never_def = get_nm_prop("ipv4.never-default") or "no"
                orig_v4_ignore_auto = get_nm_prop("ipv4.ignore-auto-routes") or "no"
                orig_v6_method = get_nm_prop("ipv6.method") or "disabled"

                nm_state_backup = {
                    "ipv4.never-default": orig_v4_never_def,
                    "ipv4.ignore-auto-routes": orig_v4_ignore_auto,
                    "ipv6.method": orig_v6_method
                }
                update_lock_state("nm_original_state", nm_state_backup)
                update_lock_state("nm_connection", active_connection_name)

                safe_print(f"{T('neutralize_route', active_connection_name)}")
                subprocess.run(["sudo", "nmcli", "connection", "modify", active_connection_name, "ipv4.never-default", "yes"], check=True, capture_output=True)
                subprocess.run(["sudo", "nmcli", "connection", "modify", active_connection_name, "ipv4.ignore-auto-routes", "yes"], check=True, capture_output=True)
                subprocess.run(["sudo", "nmcli", "connection", "modify", active_connection_name, "ipv6.method", "ignore"], check=False, capture_output=True)
                
                safe_print(f"{GREEN}{T('profile_mod', active_connection_name)}{NC}")
        except Exception as e:
            safe_print(f"{RED}Error: {e}{NC}")

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
                    cmd = ["sudo", "openvpn", "--block-ipv6", "--cd", script_dir, "--config", config_path, 
                           "--auth-user-pass", "/dev/stdin", "--mssfix", "1450", "--mute-replay-warnings"]
                    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=log, stderr=log)
                    update_lock_state("vpn_started", True)
                    try:
                        proc.stdin.write(auth_data)
                        proc.stdin.close()
                    except Exception: pass
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
                
                vpn_dns = extract_vpn_dns_from_log(script_dir)
                
                # --- NUEVO BLOQUE DE SEGURIDAD ---
                if not vpn_dns:
                    safe_print(f"{RED}{T('dns_abort')}{NC}")
                    time.sleep(8) # 8 segundos para que te dé tiempo a leerlo
                    cleanup(is_failure=True)
                    return None, False, None
                # ---------------------------------

                if not is_systemd_resolved_active(): # Ya no hace falta comprobar "if vpn_dns"
                    safe_print(f"{YELLOW}Esperando a NetworkManager (2s)...{NC}")
                    time.sleep(2)
                    
                    safe_print(f"{BLUE}  > Blindando /etc/resolv.conf (Inmutable)...{NC}")
                    try:
                        # 1. Aseguramos que el archivo no esté bloqueado de antes
                        subprocess.run(["sudo", "chattr", "-i", "/etc/resolv.conf"], check=False, stderr=subprocess.DEVNULL)
                        
                        # 2. Creamos el archivo temporal
                        temp_resolv = os.path.join(script_dir, "resolv.conf.tmp")
                        with open(temp_resolv, "w") as f:
                            f.write("# Generated by ConVPN (Kill Switch Active)\n")
                            for dns in vpn_dns:
                                f.write(f"nameserver {dns}\n")
                        
                        # 3. Machacamos el original
                        subprocess.run(["sudo", "mv", "/etc/resolv.conf", "/etc/resolv.conf.bak"], check=False, stderr=subprocess.DEVNULL)
                        subprocess.run(["sudo", "mv", temp_resolv, "/etc/resolv.conf"], check=True)
                        
                        # 4. ECHAMOS EL CANDADO (Inmutable)
                        subprocess.run(["sudo", "chattr", "+i", "/etc/resolv.conf"], check=True)
                        
                        update_lock_state("resolv_locked", True)
                        
                    except Exception as e:
                        safe_print(f"{RED}Error blindando DNS: {e}{NC}")
                # ------------------------------------------
                
                
                if not vpn_dns:
                    safe_print(f"{YELLOW}{T('dns_extract_fail')}{NC}")
                
                tun_iface = detect_tun_interface_from_log(script_dir)
                if tun_iface:
                    update_lock_state("dns_applied", True)
                    if is_systemd_resolved_active():
                        safe_print(f"{YELLOW}{T('arch_detect')}{NC}")
                        update_lock_state("arch_dns", True)
                        apply_dns_arch_native(tun_iface, vpn_dns, physical_device, script_dir)
                    else:
                        if not apply_dns_via_nm(tun_iface, vpn_dns, script_dir):
                            prompt_reload_nm(script_dir)
                else:
                    safe_print(f"{YELLOW}Warning: TUN interface not detected for DNS.{NC}")
                
                if physical_device:
                    # --- NUEVO KILL SWITCH (Sobreseguridad) ---
                    r_ip, r_port, r_proto = extract_connection_details(script_dir)
                    
                    if r_ip and r_port and tun_iface:
                        # Leemos la configuración de DoH
                        do_block_doh = config_mgr.get_doh_blocking()
                        do_block_lan = config_mgr.get_lan_blocking()
                        manage_kill_switch(physical_device, tun_iface, action="add", vpn_ip=r_ip, vpn_port=r_port, proto=r_proto, script_dir=script_dir, block_doh=do_block_doh, block_lan=do_block_lan)
                    else:
                        # NO FALLBACK - Abortar por seguridad
                        # NO FALLBACK - Abortar por seguridad
                        safe_print(f"{RED}{'='*60}{NC}")
                        safe_print(f"{RED}⚠️  {T('ks_fallback_error')} ⚠️{NC}")
                        safe_print(f"{RED}{'='*60}{NC}")
                        safe_print(f"{YELLOW}{T('ks_no_server_ip')}{NC}")
                        safe_print(f"{YELLOW}{T('ks_traffic_leak_warning')}{NC}")
                        safe_print(f"{RED}{T('ks_abort_connection')}{NC}\n")

                        # Pausa para que el usuario pueda leer los mensajes
                        time.sleep(5)

                        # Limpiamos usando la función centralizada y salimos
                        cleanup(is_failure=True)
                        return None, False, None

                if ORIGINAL_DEFAULT_ROUTE_DETAILS:
                                       
                    safe_print(f"{BLUE}{T('del_orig_route')}{NC}")
                    subprocess.run(["sudo", "ip", "route", "del", "default"], check=False, capture_output=True)
                
                if not check_and_set_default_route():
                    safe_print(f"{YELLOW}Fail route.{NC}")
                    time.sleep(3)
                    display_failure_banner(T("fail_msg_route"))
                    cleanup(is_failure=True)
                    return None, False, None

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
            ping3.ping("8.8.8.8", timeout=PING_TIMEOUT)
            safe_print(f"{GREEN}{T('ping_ok')}{NC}")
        except Exception:
            safe_print(f"{YELLOW}FAIL.{NC}")
            time.sleep(10)
            safe_print(f"{RED}{T('ping_fail')}{NC}")
            display_failure_banner(T("fail_msg_tunnel"))
            cleanup(is_failure=is_reconnecting)
            return None, False, None

        new_ip, ip_verified = "N/A", False
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
                except Exception: pass
            if ip_verified: break
            if attempt < IP_VERIFY_ATTEMPTS: time.sleep(IP_RETRY_DELAY)

        if not ip_verified:
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
                with open(os.path.join(script_dir, PORT_FILE), 'w') as f:
                    f.write(str(forwarded_port))
                safe_print(f"{GREEN}{T('port_saved', forwarded_port, PORT_FILE)}{NC}")
            except Exception: pass

        return new_ip, False, forwarded_port
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
    except Exception: return True
    current_ip = ""
    for _ in range(3):
        for service in ["ifconfig.me", "icanhazip.com", "ipinfo.io/ip"]:
            try:
                res = subprocess.run(["curl", "-s", "--max-time", str(CURL_TIMEOUT), service], capture_output=True, text=True)
                if res.returncode == 0 and is_valid_ip(res.stdout.strip()):
                    current_ip = res.stdout.strip()
                    if current_ip == expected_ip: return False
            except Exception: pass
        time.sleep(IP_RETRY_DELAY)
    safe_print(f"{RED}{T('status_ip_fail', current_ip or 'unknown')}{NC}")
    return True

def route_guardian():
    global ROUTE_CORRECTION_COUNT, LAST_RECONNECTION_TIME
    HIGH_ALERT_INTERVAL = 1
    LOW_ALERT_INTERVAL = 2
    HIGH_ALERT_DURATION = 900 
    while not GUARDIAN_STOP_EVENT.is_set():
        try:
            ip_route_output = subprocess.run(["ip", "route"], capture_output=True, text=True, check=True).stdout
            for line in ip_route_output.strip().split('\n'):
                if line.startswith('default') and 'dev tun' not in line:
                    offending_route = line.strip()
                    safe_print(f"\n{RED}{T('guardian_leak', offending_route)}{NC}")
                    subprocess.run(f"sudo ip route del {offending_route}", shell=True, check=False, capture_output=True)
                    ROUTE_CORRECTION_COUNT += 1
                    LAST_RECONNECTION_TIME = time.time()
                    try:
                        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), RECONNECTION_LOG_FILE), 'a') as f:
                            f.write(f"Correction: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(LAST_RECONNECTION_TIME))}\n")
                    except Exception: pass
                    break
        except Exception: pass
        current_interval = LOW_ALERT_INTERVAL
        if LAST_RECONNECTION_TIME is not None:
            if (time.time() - LAST_RECONNECTION_TIME) < HIGH_ALERT_DURATION:
                current_interval = HIGH_ALERT_INTERVAL
        GUARDIAN_STOP_EVENT.wait(current_interval)

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

            guardian_interval = 2
            if LAST_RECONNECTION_TIME is not None and (time.time() - LAST_RECONNECTION_TIME) < 900:
                guardian_interval = 1
            freq_color = YELLOW if guardian_interval == 1 else GREEN
            safe_print(f"  {T('lbl_guardian_freq')} {freq_color}{guardian_interval}s{NC}")

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
            safe_print(f"\n  {T('lbl_check')} {time.strftime('%H:%M:%S', time.localtime(next_check_time))} {YELLOW}({MONITOR_INTERVAL}s){NC}\n")
            safe_print(f"{GREEN}{T('status_ok')}{NC}")

            if check_connection_status(expected_ip=vpn_ip):
                reconnection_count += 1
                safe_print(f"\n{YELLOW}{T('conn_lost_retry')}{NC}")
                GUARDIAN_STOP_EVENT.set()
                guardian_thread.join(timeout=2)
                
                script_dir = os.path.dirname(os.path.realpath(__file__))
                cached_iface = get_cached_physical_interface(script_dir)
                
                if cached_iface:
                    manage_kill_switch(cached_iface, None, action="del")

                cleanup(is_failure=False)
                create_lock_file()
                time.sleep(3)
                new_ip, new_dns_fallback, new_port = establish_connection(selected_file, selected_location, initial_ip, is_reconnecting=True)
                if not new_ip:
                    safe_print(f"\n{RED}{T('reconn_fail_kill')}{NC}")
                    time.sleep(5)
                    return
                vpn_ip, forwarded_port = new_ip, new_port
                ROUTE_CORRECTION_COUNT = 0
                LAST_RECONNECTION_TIME = None
                last_analysis_time = 0
                analysis_result_block = None
                send_critical_notification(T("notif_reconn_title"), T("notif_reconn_msg", forwarded_port))
                display_success_banner(selected_location, initial_ip, vpn_ip, True, reconnection_count)
                #### Ejecutar script post-conexión tras reconexión
                script_dir = os.path.dirname(os.path.realpath(__file__))
                run_post_script(ConfigManager(script_dir))
                ####
                GUARDIAN_STOP_EVENT.clear()
                guardian_thread = threading.Thread(target=route_guardian, daemon=True)
                guardian_thread.start()
                time.sleep(4)
                continue
            
            safe_print(f"{YELLOW}{T('ctrl_c_exit')}{NC}", dynamic=True)
            time.sleep(MONITOR_INTERVAL)
    except KeyboardInterrupt:
        safe_print(f"\n{YELLOW}Stop signal.{NC}")
        GUARDIAN_STOP_EVENT.set()
        guardian_thread.join(timeout=2)
        cleanup(is_failure=False)
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
    if num_locations == 0: safe_print(f"{RED}{T('menu_none')}{NC}")
    else:
        try: terminal_width = os.get_terminal_size().columns
        except OSError: terminal_width = 80
        max_digits = len(str(num_locations))
        max_item_width = 0
        for i, location in enumerate(locations):
            item_length = len(f"  {i + 1:>{max_digits}}) {location}")
            if item_length > max_item_width: max_item_width = item_length
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
                    part = f"  {num:>{max_digits}}) {locations[index]}"
                    if last_choice is not None and num == last_choice: part = f"{YELLOW}{part}{NC}"
                    if j < num_columns - 1: line_parts.append(f"{part:<{single_col_total_width + (len(YELLOW)+len(NC) if last_choice==num else 0)}}")
                    else: line_parts.append(part)
            safe_print("".join(line_parts))

    safe_print("")
    safe_print(f"{RED}{T('ctrl_c_exit')}{NC}")
    
    prompt = T("menu_prompt", len(locations), YELLOW + locations[last_choice - 1] + NC) if last_choice else T("menu_prompt_no_def", len(locations))
    
    while True:
        try:
            choice_str = input(prompt)
            if choice_str.lower() == 'm': return 'MENU'
            
            if not choice_str and last_choice: return last_choice
            
            choice = int(choice_str)
            if 1 <= choice <= len(locations): return choice
            safe_print(f"{RED}Error.{NC}")
        except ValueError: safe_print(f"{RED}Error.{NC}")
        except KeyboardInterrupt:
            GUARDIAN_STOP_EVENT.set()
            cleanup(is_failure=False)
            safe_print(f"\n{YELLOW}{T('final_exit')}{NC}")
            time.sleep(5)
            sys.exit(0)

def create_desktop_launcher():
    clear_screen()
    safe_print(f"{BLUE}======================================={NC}")
    safe_print(f"{BLUE}    {T('menu_opt_launcher')}")
    safe_print(f"{BLUE}======================================={NC}")
    
    try:
        script_path = os.path.realpath(sys.argv[0])
        script_dir = os.path.dirname(script_path)
        python_exec = sys.executable
        
        launcher_dir = os.path.expanduser("~/.local/share/applications")
        if not os.path.exists(launcher_dir):
            os.makedirs(launcher_dir)
        
        for filename in os.listdir(launcher_dir):
            if filename.startswith("convpn") and filename.endswith(".desktop"):
                try: os.remove(os.path.join(launcher_dir, filename))
                except: pass

        launcher_path = os.path.join(launcher_dir, "convpn_assistant.desktop")
        
        content = f"""[Desktop Entry]
Version=1.0
Type=Application
Name=Asistente VPN (v{VERSION})
Comment=Gestor de conexiones OpenVPN automatizado
Exec="{python_exec}" "{script_path}"
Path={script_dir}
Icon=network-vpn
Terminal=false
Categories=Network;ConsoleOnly;
"""
        with open(launcher_path, "w") as f:
            f.write(content)
        
        os.chmod(launcher_path, 0o755)
        safe_print(f"\n{GREEN}{T('launcher_created', launcher_path)}{NC}")
        
        if which("update-desktop-database"):
            subprocess.run(["update-desktop-database", launcher_dir], stderr=subprocess.DEVNULL)
            
    except Exception as e:
        safe_print(f"\n{RED}{T('launcher_error', e)}{NC}")
    
    time.sleep(3)

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
    sample = ovpn_files[0].replace('.ovpn', '')
    safe_print(f"{YELLOW}{T('cfg_sample')}{NC}{sample}\n")
    safe_print(T('cfg_fmt_q'))
    safe_print(T('cfg_fmt_a'))
    safe_print(T('cfg_fmt_b'))
    while True:
        fmt = input("> ").upper()
        if fmt in ['A', 'B']: break
    sep = input(T('cfg_sep_q'))
    if not sep: sep = "-"
    parts = sample.split(sep)
    safe_print(f"\n{BLUE}{T('cfg_parts')}{NC}")
    for i, p in enumerate(parts): safe_print(f"  {i}: {p}")
    while True:
        try:
            c = int(input(f"\n{T('cfg_idx_city')}"))
            if 0 <= c < len(parts): break
        except ValueError: pass
    c_idx = None
    if fmt == 'A':
        while True:
            try:
                co = int(input(f"{T('cfg_idx_country')}"))
                if 0 <= co < len(parts): 
                    c_idx = co
                    break
            except ValueError: pass
    config_mgr.update_display_config(fmt, sep, c, c_idx)
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
        else: safe_print(f"\n{RED}{T('cfg_creds_err')}{NC}")
    except Exception: pass
    time.sleep(2)

def configure_post_script_screen(config_mgr):
    clear_screen()
    safe_print(f"{BLUE}======================================={NC}")
    safe_print(f"{BLUE}    {T('cfg_post_title')}")
    safe_print(f"{BLUE}======================================={NC}")
    
    current = config_mgr.get_post_script()
    safe_print(f"{T('cfg_post_current')}")
    if current:
        safe_print(f"{GREEN}{current}{NC}")
    else:
        safe_print(f"{YELLOW}{T('cfg_post_none')}{NC}")
    
    print("") 
    
    safe_print(f"{YELLOW}{T('cfg_post_info')}{NC}")
    safe_print(f"{PINK}{T('cfg_post_warn_spaces')}{NC}\n")
    
    path = input(T('cfg_post_prompt')).strip()
    
    if len(path) >= 2 and ((path.startswith("'") and path.endswith("'")) or \
                           (path.startswith('"') and path.endswith('"'))):
        path = path[1:-1]
    path = path.replace("\\ ", " ")

    if path and not os.path.isabs(path):
        script_dir = os.path.dirname(os.path.realpath(__file__))
        potential_path = os.path.join(script_dir, path)
        if os.path.exists(potential_path):
            path = potential_path

    if not path:
        safe_print(f"\n{GREEN}{T('cfg_post_kept')}{NC}")
    elif path.lower() == 'd':
        config_mgr.set_post_script(None)
        safe_print(f"\n{YELLOW}{T('cfg_post_removed')}{NC}")
    else:
        if os.path.exists(path) and os.access(path, os.X_OK):
            config_mgr.set_post_script(path)
            safe_print(f"\n{GREEN}{T('cfg_post_saved', path)}{NC}")
        else:
            safe_print(f"\n{RED}{T('cfg_post_err')}{NC}")
            config_mgr.set_post_script(path)
            
    time.sleep(2)
    
def configure_doh_screen(config_mgr):
    clear_screen()
    safe_print(f"{BLUE}======================================={NC}")
    safe_print(f"{BLUE}    {T('cfg_doh_title')}")
    safe_print(f"{BLUE}======================================={NC}")
    safe_print(f"{YELLOW}{T('cfg_doh_info')}{NC}\n")
    
    current = config_mgr.get_doh_blocking()
    status_text = T('cfg_doh_on') if current else T('cfg_doh_off')
    color = GREEN if current else RED
    safe_print(f"{T('cfg_doh_status')}{color}{status_text}{NC}\n")
    
    choice = input(T('cfg_doh_prompt')).lower()
    if choice.startswith('s') or choice.startswith('y'):
        new_state = not current
        config_mgr.set_doh_blocking(new_state)
        new_text = T('cfg_doh_on') if new_state else T('cfg_doh_off')
        safe_print(f"\n{GREEN}{T('cfg_doh_saved', new_text)}{NC}")
        time.sleep(2)
    else:
        time.sleep(1)
        
def configure_lan_screen(config_mgr):
    clear_screen()
    safe_print(f"{BLUE}======================================={NC}")
    safe_print(f"{BLUE}    {T('cfg_lan_title')}")
    safe_print(f"{BLUE}======================================={NC}")
    safe_print(f"{YELLOW}{T('cfg_lan_info')}{NC}\n")
    
    current = config_mgr.get_lan_blocking()
    status_text = T('cfg_lan_on') if current else T('cfg_lan_off')
    color = GREEN if current else RED
    safe_print(f"{T('cfg_lan_status')}{color}{status_text}{NC}\n")
    
    choice = input(T('cfg_lan_prompt')).lower()
    if choice.startswith('s') or choice.startswith('y'):
        new_state = not current
        config_mgr.set_lan_blocking(new_state)
        new_text = T('cfg_lan_on') if new_state else T('cfg_lan_off')
        safe_print(f"\n{GREEN}{T('cfg_lan_saved', new_text)}{NC}")
        time.sleep(2)
    else:
        time.sleep(1)

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
        except KeyboardInterrupt: sys.exit(0)
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
        safe_print(f"  4) {T('menu_opt_post')}")
        safe_print(f"  5) {T('menu_opt_launcher')}")
        safe_print(f"  6) {T('menu_opt_doh')}")
        safe_print(f"  7) {T('menu_opt_lan')}")
        safe_print(f"  8) {T('menu_opt_back')}")
        try:
            sel = input("\n> ")
            if not sel: break
            if sel == "1": configure_display_screen(config_mgr, script_dir)
            elif sel == "2": select_language_screen(config_mgr)
            elif sel == "3": configure_credentials_screen(config_mgr)
            elif sel == "4": configure_post_script_screen(config_mgr)
            elif sel == "5": create_desktop_launcher()
            elif sel == "6": configure_doh_screen(config_mgr)
            elif sel == "7": configure_lan_screen(config_mgr)
            elif sel == "8": break    
        except KeyboardInterrupt: break
        
def run_post_script(config_mgr):
    post_script = config_mgr.get_post_script()
    if post_script:
        # Resolver ruta si es relativa
        if not os.path.isabs(post_script):
            script_dir = os.path.dirname(os.path.realpath(__file__))
            post_script = os.path.join(script_dir, post_script)

        if os.path.exists(post_script):
            # Obtenemos el usuario actual para mostrarlo en el log
            current_user = getpass.getuser()
            safe_print(f"{BLUE}{T('exec_post', current_user)}{NC}")
            
            # Ejecutamos el script directamente. Heredará el usuario actual.
            cmd = [post_script]
            
            try:
                # start_new_session=True permite que el script siga corriendo 
                # independientemente de este proceso padre.
                subprocess.Popen(cmd, start_new_session=True)
            except Exception as e:
                safe_print(f"{RED}Error: {e}{NC}")

def main():
    global CURRENT_LANG
    script_dir = os.path.dirname(os.path.realpath(__file__))
    
    # --- CONTROL DE INSTANCIA ÚNICA (LOCKFILE INTELIGENTE) ---
    lock_path = os.path.join(script_dir, LOCK_FILE)
    
    if os.path.exists(lock_path):
        try:
            with open(lock_path, 'r') as f:
                lock_data = json.load(f)
                old_pid = lock_data.get("pid")
            
            is_alive = False
            if old_pid:
                try:
                    os.kill(old_pid, 0)
                    is_alive = True
                except OSError as e:
                    if e.errno == errno.EPERM: is_alive = True
                    elif e.errno == errno.ESRCH: is_alive = False
                    else: is_alive = False

            if is_alive:
                safe_print(f"\n{PINK}[!] ERROR: Ya hay una instancia activa (PID {old_pid}).{NC}")
                safe_print(f"{YELLOW}Si crees que es un error, borra el archivo '{LOCK_FILE}'.{NC}")
                time.sleep(3)
                sys.exit(1)
            else:
                safe_print(f"{YELLOW}Detectado cierre incorrecto previo (PID {old_pid}). Limpiando sistema...{NC}")
                cleanup(is_failure=False, state_override=lock_data)

        except (json.JSONDecodeError, ValueError):
            pass

    create_lock_file()

    config_mgr = ConfigManager(script_dir)
    saved_lang = config_mgr.get_language()
    if saved_lang: CURRENT_LANG = saved_lang
    else: select_language_screen(config_mgr)

    if not all(which(cmd) for cmd in ["openvpn", "curl", "sudo", "stty", "nmcli", "ip", "iptables"]):
        safe_print(f"{RED}{T('error_lib', 'openvpn/curl/sudo/stty/nmcli/ip/iptables')}{NC}")
        sys.exit(1)

    clear_screen()
    safe_print(f"{BLUE}====================================================={NC}")
    safe_print(f"{BLUE}      {T('welcome_title')} (v{VERSION})      {NC}")
    safe_print(f"{BLUE}====================================================={NC}")
    safe_print(f"\n{YELLOW}{T('guide_title')}{NC}")
    safe_print(f"\n{GREEN}{T('guide_1')}{NC}")
    safe_print(f"{GREEN}{T('guide_2')}{NC}")
    safe_print(f"{GREEN}{T('guide_3')}{NC}")
    safe_print(f"{GREEN}{T('guide_4')}{NC}")

    safe_print(f"\n{RED}--------------------------------------------------------------------{NC}")
    safe_print(f"{RED}{T('sudo_simple')}{NC}")
    safe_print(f"{RED}--------------------------------------------------------------------{NC}\n")
    if subprocess.run(["sudo", "-v"], capture_output=True).returncode != 0:
        safe_print(f"{RED}{T('sudo_error')}{NC}")
        sys.exit(1)
    
    threading.Thread(target=keep_sudo_alive, daemon=True).start()

    backup_original_dns(script_dir, os.path.join(script_dir, DNS_BACKUP_FILE))

    safe_print(f"{BLUE}{T('check_conn')}{NC}")
    initial_ip = None
    
    conn_success = False
    for i in range(2):
        try:
            res = subprocess.run(["curl", "-s", "--max-time", str(CURL_TIMEOUT), "ifconfig.me"], capture_output=True, text=True, check=True)
            if is_valid_ip(res.stdout.strip()):
                initial_ip = res.stdout.strip()
                conn_success = True
                safe_print(f"{GREEN}{T('conn_confirmed')}{NC}")
                break
        except Exception:
            if i == 0: time.sleep(5)

    if not conn_success:
        safe_print(f"{YELLOW}{T('repair_attempt')}{NC}")
        
        iface = get_cached_physical_interface(script_dir)
        if iface:
            manage_kill_switch(iface, None, action="del")
            if is_systemd_resolved_active():
                subprocess.run(["sudo", "resolvectl", "revert", iface], check=False, stderr=subprocess.DEVNULL)
        try:
            safe_print(T('repair_restoring'))
            if is_systemd_resolved_active():
                 subprocess.run(["sudo", "resolvectl", "flush-caches"], check=False, stderr=subprocess.DEVNULL)
            
            nmcli_output = subprocess.run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"], capture_output=True, text=True).stdout
            for line in nmcli_output.strip().split('\n'):
                parts = line.split(':')
                if len(parts) > 1 and parts[1].lower() != 'lo' and not parts[1].lower().startswith('tun'):
                    subprocess.run(["sudo", "nmcli", "connection", "modify", parts[0], "ipv4.never-default", "no"], check=True, capture_output=True)
                    subprocess.run(["sudo", "nmcli", "connection", "modify", parts[0], "ipv4.ignore-auto-routes", "no"], check=True, capture_output=True)
                    subprocess.run(["sudo", "nmcli", "connection", "modify", parts[0], "ipv6.method", "auto"], check=True, capture_output=True)
            
            safe_print(T('repair_reset'))
            subprocess.run(["sudo", "nmcli", "networking", "off"], check=True, capture_output=True)
            time.sleep(10)
            subprocess.run(["sudo", "nmcli", "networking", "on"], check=True, capture_output=True)
            time.sleep(20) 
            
            safe_print(T('repair_verify'))
            res = subprocess.run(["curl", "-s", "--max-time", str(CURL_TIMEOUT), "ifconfig.me"], capture_output=True, text=True, check=True)
            if not is_valid_ip(res.stdout.strip()): raise ValueError("Invalid IP")
            initial_ip = res.stdout.strip()
            safe_print(f"{GREEN}{T('repair_success')}{NC}")
            time.sleep(4)
        except Exception as e:
            safe_print(f"\r\033[K{RED}{T('repair_fail')}{NC}")
            safe_print(f"Error: {e}")
            cleanup(is_failure=False)
            safe_print(f"\n{YELLOW}{T('closing')}{NC}")
            time.sleep(15)
            sys.exit(1)

    vpn_user, vpn_pass = config_mgr.get_credentials()
    if not vpn_user or not vpn_pass:
        safe_print(f"\n{YELLOW}No se detectaron credenciales guardadas.{NC}")
        configure_credentials_screen(config_mgr)

    while True:
        create_lock_file()
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
        if last_choice and (last_choice < 1 or last_choice > len(locations)): last_choice = None
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
############          
            run_post_script(config_mgr)


            time.sleep(12)
############            
            monitor_connection(selected_file, selected_location, initial_ip, new_ip, dns_fallback_used, forwarded_port)
        else:
            safe_print(f"\n{YELLOW}Menu 5s...{NC}")
            time.sleep(5)

if __name__ == "__main__":
    if "--run-in-terminal" not in sys.argv:
        script_path = os.path.realpath(__file__)
        terminals = {
            "gnome-terminal": "--", "konsole": "-e", "xfce4-terminal": "--hold -e",
            "xterm": "-e", "alacritty": "-e", "kitty": "--hold",        
        }
        for term, args in terminals.items():
            if which(term):
                try:
                    cmd = f"{term} {args} \"python3 '{script_path}' --run-in-terminal\"" if term == "xfce4-terminal" else f"{term} {args} python3 '{script_path}' --run-in-terminal"
                    subprocess.run(cmd, shell=True, check=True)
                    sys.exit(0)
                except Exception as e: safe_print(f"{RED}{T('term_error')}: {e}{NC}")
        safe_print(f"{RED}{T('term_error')}{NC}")
        safe_print(f"{YELLOW}{T('term_run', script_path)}{NC}")
        sys.exit(1)
    else:
        try: main()
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
