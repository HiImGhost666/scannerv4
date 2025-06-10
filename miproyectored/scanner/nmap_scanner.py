import subprocess
import xml.etree.ElementTree as ET
import platform
import os
import time
import json
import re
from typing import List, Optional

from ..model.device import Device
from ..util.data_normalizer import DataNormalizer
from ..risk.risk_analyzer import RiskAnalyzer
import logging
logger = logging.getLogger('miproyectored')

class NmapScanner:
    def __init__(self, nmap_path=None):
        self.data_normalizer = DataNormalizer()
        self.risk_analyzer = RiskAnalyzer()  # Mantener la instancia si se usa en otros métodos no estáticos

        if nmap_path:
            self.nmap_path = nmap_path
            if not self._is_nmap_available(self.nmap_path):
                 print(f"[ERROR] Nmap no parece estar disponible en la ruta especificada: {nmap_path}")
                 self.nmap_path = None # Reset path if not available
        else:
            self.nmap_path = self._find_nmap_path()

        if not self.nmap_path:
            print("[ERROR] Nmap no encontrado en el PATH del sistema ni en ubicaciones comunes. "
                  "Por favor, instala Nmap y asegúrate de que esté en el PATH, "
                  "o proporciona la ruta explícitamente al constructor de NmapScanner.")
            # Considera lanzar una excepción o manejar el error de otra forma

    def _find_nmap_path(self):
        os_name = platform.system()
        command = "nmap"

        if os_name == "Windows":
            # Try with "nmap" (if in PATH)
            if self._is_nmap_available(command): return command
            # Check common paths on Windows
            common_path_program_files = "C:\\Program Files\\Nmap\\nmap.exe"
            if os.path.exists(common_path_program_files) and self._is_nmap_available(common_path_program_files): return common_path_program_files
            common_path_program_files_x86 = "C:\\Program Files (x86)\\Nmap\\nmap.exe"
            if os.path.exists(common_path_program_files_x86) and self._is_nmap_available(common_path_program_files_x86): return common_path_program_files_x86
        else: # Linux, macOS
            if self._is_nmap_available(command): return command
            # You could check /usr/bin/nmap, /usr/local/bin/nmap, etc.
            common_path_usr_bin = "/usr/bin/nmap"
            if os.path.exists(common_path_usr_bin) and self._is_nmap_available(common_path_usr_bin): return common_path_usr_bin
            common_path_usr_local_bin = "/usr/local/bin/nmap"
            if os.path.exists(common_path_usr_local_bin) and self._is_nmap_available(common_path_usr_local_bin): return common_path_usr_local_bin

        return None

    def _is_nmap_available(self, command_or_path):
        try:
            # Use subprocess.run for better control and error handling
            result = subprocess.run([command_or_path, "-V"], capture_output=True, text=True, check=False)
            # Check if the command ran successfully (exit code 0) and produced some output
            return result.returncode == 0 and (result.stdout or result.stderr)
        except FileNotFoundError:
            # This exception is raised if the command_or_path is not found
            return False
        except Exception as e:
            # Catch other potential errors during execution
            # print(f"Error verifying Nmap at '{command_or_path}': {e}")
            return False

    def quick_scan(self, target: str) -> List[str]:
        """Realiza un escaneo rápido para encontrar hosts activos."""
        try:
            # Usar -sn (Ping Scan) para descubrir hosts que están activos,
            # independientemente de si tienen puertos abiertos comunes.
            # -PE -PP -PM: Diferentes tipos de sondas ICMP (Echo, Timestamp, Netmask)
            # -PS21,22,23,25,80,110,135,139,443,3389,8080: TCP SYN Ping a puertos comunes
            # -PA80,443,3389: TCP ACK Ping a puertos comunes
            # Esto es más completo que solo -sn.
            command = [
                self.nmap_path,
                "-T4",  # Timing template (agresivo)
                "-sn",  # Ping Scan - no hacer escaneo de puertos
                # Añadir más tipos de sondas para mejorar el descubrimiento
                "-PE", "-PP", "-PM", # Sondas ICMP
                "-PS21,22,23,25,80,110,135,139,443,3389,5900,8080", # TCP SYN Ping
                "-PA80,443,3389,5900", # TCP ACK Ping
                "-n",   # No DNS resolution
                "-oX", "-", # Salida XML a stdout
                target
            ]
            logger.info(f"Ejecutando quick_scan con comando: {' '.join(command)}")
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            
            active_ips = []
            if result.returncode == 0 and result.stdout:
                try:
                    root = ET.fromstring(result.stdout)
                    for host_node in root.findall(".//host[status[@state='up']]"):
                        # Con -sn, solo necesitamos verificar que el host esté 'up'
                        addr_node = host_node.find("address[@addrtype='ipv4']")
                        if addr_node is not None and addr_node.get("addr"):
                            active_ips.append(addr_node.get("addr"))
                except ET.ParseError as e:
                    logger.error(f"Error parseando XML de quick_scan: {e}\nSalida XML parcial: {result.stdout[:500]}")
            elif result.returncode != 0:
                logger.error(f"Error en quick_scan (código {result.returncode}): {result.stderr}")

            logger.info(f"Quick_scan encontró {len(active_ips)} IPs activas: {active_ips}")
            return active_ips
            
        except Exception as e:
            logger.error(f"Error en quick_scan: {e}", exc_info=True)
            return []

    def detailed_scan(self, ip: str) -> Optional[Device]:
        """Realiza un escaneo detallado de un host específico."""
        try:
            # Escaneo más detallado para un solo host
            command = [
                self.nmap_path,
                "-sS",     # SYN scan
                "-sV",      # Version detection
                "--version-all",  # Try all version detection probes
                "--version-intensity", "9",  # Maximum version detection intensity
                "--version-light",  # Faster version detection (less reliable but much faster)
                "-O",       # OS detection
                "-p-",       # Todos los puertos
                "-A",        # Aggressive scan options
                "--max-os-tries", "3",  # More OS detection attempts
                "-T4",       # Aggressive timing
                "--host-timeout", "500s",  # Increased timeout per host
                "--script-timeout", "50s",  # Timeout for scripts
                "--script=default,banner,http-title,ssl-cert,ssh-auth-methods,smb-os-discovery,smb-system-info,dns-service-discovery,nbstat,snmp-info,http-headers",
                "--min-rate", "1000",  # Minimum packet rate
                "--max-retries", "3",   # More retries
                "-oX", "-",   # Output XML to stdout
                ip
            ]
            
            print(f"Escaneando {ip} con comando: {' '.join(command)}")  # Debug
            result = subprocess.run(command, capture_output=True, text=True)
            logger.debug(f"Raw Nmap XML output for {ip} (return code {result.returncode}):\n{result.stdout}")
            if result.stderr:
                logger.debug(f"Nmap stderr for {ip}:\n{result.stderr}")
            
            if result.returncode != 0:
                print(f"Error en el escaneo de {ip}: {result.stderr}")  # Debug
                return None
                
            # Parsear XML y crear Device
            try:
                root = ET.fromstring(result.stdout)
            except ET.ParseError as e:
                print(f"[ERROR] Error parseando XML para {ip}: {e}")
                print(f"[DEBUG] XML recibido: {result.stdout[:200]}...")
                return None
            except Exception as e:
                print(f"[ERROR] Error inesperado al procesar XML para {ip}: {e}")
                return None
                
            # Buscar el host en el XML
            host = root.find('.//host')
            if host is not None and host.find(".//status[@state='up']") is not None:
                return self._parse_host(host)
            else:
                print(f"No se encontró información del host para {ip}")  # Debug
                return None
            
        except Exception as e:
            print(f"Error en detailed_scan para {ip}: {e}")
            return None

    def scan(self, target, on_device_found=None):
        """Realiza un escaneo de red mostrando progreso en tiempo real."""
        if not self.nmap_path:
            print("Error: No se encontró nmap en el sistema.")
            return []

        # Fase 1: Descubrimiento rápido de hosts con ARP
        arp_scan_command = [
            self.nmap_path,
            "-sn",               # No port scan
            "-PR",              # ARP scan
            "-T4",              # Aggressive timing
            "--min-parallelism=10",
            "--max-retries=3",
            "-oX", "-"          # XML output
        ]

        print("=" * 50)
        print("[INFO] Fase 1: Descubrimiento ARP de hosts...")
        
        devices = []
        active_ips = set()
        
        try:
            with subprocess.Popen(
                arp_scan_command + [target],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            ) as process:
                current_xml = ""
                
                while True:
                    output = process.stdout.read(1)
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        current_xml += output
                        if "</host>" in current_xml:
                            try:
                                host_end = current_xml.find("</host>") + 7
                                host_xml = current_xml[:host_end]
                                root = ET.fromstring(host_xml)
                                
                                ip = root.find(".//address[@addrtype='ipv4']")
                                if ip is not None:
                                    ip_addr = ip.get('addr')
                                    if ip_addr:
                                        active_ips.add(ip_addr)
                                        
                            except ET.ParseError as e:
                                print(f"[ERROR] Error parseando XML del host: {e}")
                                print(f"XML fragmento: {current_xml[:200]}...")
                            except Exception as e:
                                print(f"[ERROR] Error inesperado en fase 1: {e}")
                            finally:
                                current_xml = current_xml[host_end:]
                
                # Check for any errors
                _, stderr = process.communicate()
                if process.returncode != 0:
                    print(f"[ERROR] Error en el escaneo ARP: {stderr}")
                    return []
        except Exception as e:
            print(f"[ERROR] Error al ejecutar el escaneo ARP: {e}")
            return []

        print(f"[INFO] Encontrados {len(active_ips)} hosts activos")
        if not active_ips:
            print("[INFO] No se encontraron hosts activos para escanear")
            return []

        # Fase 2: Escaneo detallado en paralelo
        max_parallel = 5  # Número máximo de escaneos paralelos
        active_processes = {}
        completed_ips = set()

        # Configuración base para el escaneo detallado
        detailed_scan_base = [
            self.nmap_path,
            "-sS",                # TCP SYN scan
            "-sV",               # Version detection
            "-O",                # OS Detection
            "-A",                # Enable OS detection, version detection, script scanning
            "-n",                # No DNS resolution
            "-Pn",               # Treat all hosts as online
            "-p-",               # All ports
            "--version-all",     # Try every version detection probe
            "--osscan-guess",    # Guess OS more aggressively
            "--max-os-tries=5",  # More OS detection attempts
            "-T4",               # Aggressive timing
            "--min-rate=300",    # Minimum packet rate
            "--max-retries=3",   # More retries
            "--host-timeout=300s", # 5 minutes timeout per host
            # Scripts específicos para obtener más información
            "--script=default,banner,http-title,ssl-cert,ssh-auth-methods,smb-os-discovery,smb-system-info,dns-service-discovery,nbstat,snmp-info,http-headers",
            "-oX", "-"           # XML output
        ]

        print("\n[INFO] Fase 2: Iniciando escaneos detallados en paralelo...")

        while len(completed_ips) < len(active_ips):
            # Iniciar nuevos escaneos si hay espacio
            for ip in active_ips:
                if ip not in completed_ips and ip not in active_processes and len(active_processes) < max_parallel:
                    print(f"\n[INFO] Iniciando escaneo detallado de {ip}...")
                    try:
                        process = subprocess.Popen(
                            detailed_scan_base + [ip],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            bufsize=1,
                            universal_newlines=True
                        )
                        active_processes[ip] = {
                            'process': process,
                            'xml': "",
                            'start_time': time.time()
                        }
                    except Exception as e:
                        print(f"[ERROR] Error al iniciar el escaneo para {ip}: {e}")
                        completed_ips.add(ip)

            # Verificar procesos activos
            for ip in list(active_processes.keys()):
                if ip in completed_ips:
                    continue
                    
                process_info = active_processes[ip]
                process = process_info['process']
                
                # Leer salida disponible
                try:
                    while True:
                        output = process.stdout.read1(1024).decode('utf-8', errors='ignore')
                        if not output:
                            break
                        process_info['xml'] += output

                    # Verificar si el proceso ha terminado
                    if process.poll() is not None:
                        # Procesar la salida XML
                        if "</host>" in process_info['xml']:
                            try:
                                root = ET.fromstring(process_info['xml'])
                                host_element = root.find('.//host')
                                if host_element is not None:
                                    device = self._parse_host(host_element)
                                    if device and on_device_found:
                                        on_device_found(device)
                            except Exception as e:
                                print(f"[ERROR] Error procesando resultados para {ip}: {e}")
                        
                        # Limpiar
                        del active_processes[ip]
                        completed_ips.add(ip)
                        
                except Exception as e:
                    print(f"[ERROR] Error leyendo salida del proceso para {ip}: {e}")
                    del active_processes[ip]
                    completed_ips.add(ip)
            
            # Pequeña pausa para no saturar la CPU
            time.sleep(0.1)
        
        # Asegurarse de que todos los procesos hayan terminado
        for process_info in active_processes.values():
            try:
                process_info['process'].wait(timeout=1)
            except Exception:
                pass
        
        return devices

    def _parse_host(self, host):
        """
        Parsea un host desde su XML.
        
        Args:
            host: Elemento XML del host a parsear
            
        Returns:
            Device: Objeto Device con la información del host o None si hay error
        """
        try:
            # Obtener dirección IP
            ip_address = None
            address_elem = host.find(".//address[@addrtype='ipv4']")
            if address_elem is not None:
                ip_address = address_elem.get('addr')
            
            if not ip_address:
                print("[WARNING] No se pudo obtener la dirección IP del host")
                return None
                
            # Obtener hostname si existe
            hostname_elem = host.find(".//hostname")
            hostname = hostname_elem.get('name') if hostname_elem is not None else ip_address
            
            # Crear dispositivo
            device = Device(ip_address=ip_address, hostname=hostname)
            
            # MAC Address y Vendor
            mac = host.find(".//address[@addrtype='mac']")
            if mac is not None:
                device.mac_address = mac.get('addr', '').upper()
                device.vendor = mac.get('vendor', '')
                
                # Si no se encontró el vendedor, intentar obtenerlo del nombre del host
                if not device.vendor and device.mac_address:
                    try:
                        from miproyectored.util.mac_manufacturer_manager import MacManufacturerManager
                        mac_manager = MacManufacturerManager()
                        device.vendor = mac_manager.get_manufacturer(device.mac_address)
                    except Exception as e:
                        print(f"[WARNING] Error al obtener fabricante para MAC {device.mac_address}: {e}")
            
            # Establecer estado basado en la respuesta del host
            status = host.find(".//status")
            if status is not None:
                device.status = status.get('state', 'unknown').capitalize()
            else:
                device.status = "Active"  # Asumir activo si no se especifica
                
            # Detección de SO
            os_info = host.find(".//osmatch")
            if os_info is not None:
                device.os_info = self.data_normalizer.normalize_os_info(os_info)
            
            # Procesar puertos
            device = self._create_device_from_host(host, ip_address)
            
            return device
            
        except Exception as e:
            print(f"[ERROR] Error parseando host: {str(e)}")
            import traceback
            traceback.print_exc()
            return None


    def _parse_single_host(self, host_xml):
        """
        Parsea un único host desde su XML.
        
        Args:
            host_xml (str): XML del host a parsear
            
        Returns:
            Device: Objeto Device con la información del host o None si hay error
        """
        print("[DEBUG] Iniciando parseo de host XML")
        try:
            root = ET.fromstring(host_xml)
            
            # Verificar si el host está activo
            status = root.find(".//status")
            if status is None or status.get('state') != 'up':
                return None
                
            # Obtener dirección IP
            ip = root.find(".//address[@addrtype='ipv4']")
            if ip is None:
                return None
                
            ip_address = ip.get('addr')
            if not ip_address:
                return None
                
            # Obtener hostname si existe
            hostname_elem = root.find(".//hostname")
            hostname = hostname_elem.get('name') if hostname_elem is not None else ip_address
            
            # Crear dispositivo
            device = Device(ip_address=ip_address, hostname=hostname)
            
            # MAC Address y Vendor
            mac = root.find(".//address[@addrtype='mac']")
            if mac is not None:
                device.mac_address = mac.get('addr', '').upper()
                device.vendor = mac.get('vendor', '')
                
                # Si no se encontró el vendedor, intentar obtenerlo del nombre del host
                if not device.vendor and device.mac_address:
                    try:
                        from miproyectored.util.mac_manufacturer_manager import MacManufacturerManager
                        mac_manager = MacManufacturerManager()
                        device.vendor = mac_manager.get_manufacturer(device.mac_address)
                    except Exception as e:
                        print(f"[WARNING] Error al obtener fabricante para MAC {device.mac_address}: {e}")
            
            # Intentar obtener MAC de scripts si no se encontró
            if not device.mac_address:
                print("[DEBUG] Buscando MAC en scripts NBT/SMB...")
                for script in root.findall(".//script"):
                    script_id = script.get('id', '').lower()
                    output = script.get('output', '')
                    
                    # Patrones para diferentes formatos de salida de MAC
                    mac_patterns = [
                        r'MAC\s*[=:>]\s*([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})',
                        r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})',
                        r'MAC\s*Address\s*:\s*([0-9A-Fa-f]{12})',
                        r'([0-9A-Fa-f]{12})'
                    ]
                    
                    for pattern in mac_patterns:
                        mac_match = re.search(pattern, output, re.IGNORECASE)
                        if mac_match:
                            mac = mac_match.group(1).replace('-', ':')
                            if ':' not in mac and len(mac) == 12:  # Formato sin separadores
                                mac = ':'.join([mac[i:i+2] for i in range(0, 12, 2)])
                            device.mac_address = mac.upper()
                            print(f"[DEBUG] MAC encontrada en script {script_id}: {device.mac_address}")
                            
                            # Intentar obtener el vendedor de la MAC
                            if not device.vendor:
                                try:
                                    from miproyectored.util.mac_manufacturer_manager import MacManufacturerManager
                                    mac_manager = MacManufacturerManager()
                                    device.vendor = mac_manager.get_manufacturer(device.mac_address)
                                    if device.vendor:
                                        print(f"[DEBUG] Fabricante detectado: {device.vendor}")
                                except Exception as e:
                                    print(f"[WARNING] Error al obtener fabricante para MAC {device.mac_address}: {e}")
                            break
                    
                    if device.mac_address:
                        break
                        
                # Si aún no se encontró MAC, intentar con ARP
                if not device.mac_address and platform.system() == 'Windows':
                    print("[DEBUG] Intentando obtener MAC con ARP...")
                    try:
                        arp_output = subprocess.check_output(['arp', '-a', ip_address], text=True)
                        for line in arp_output.split('\n'):
                            if ip_address in line:
                                mac_match = re.search(r'([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}', line)
                                if mac_match:
                                    device.mac_address = mac_match.group(0).replace('-', ':').upper()
                                    print(f"[DEBUG] MAC encontrada con ARP: {device.mac_address}")
                                    break
                    except Exception as e:
                        print(f"[WARNING] Error al ejecutar ARP: {e}")
            
            # OS Detection
            os_info = {}
            os_matches = root.findall(".//osmatch")
            if os_matches:
                best_match = max(os_matches, key=lambda x: float(x.get('accuracy', 0)))
                os_info['name'] = best_match.get('name', '')
                os_info['accuracy'] = best_match.get('accuracy', '')
                
                os_classes = best_match.findall(".//osclass")
                if os_classes:
                    best_class = os_classes[0]
                    device.os_type = best_class.get('type', '')
                    device.os_vendor = best_class.get('vendor', '')
                    device.os_family = best_class.get('osfamily', '')
                    device.os_gen = best_class.get('osgen', '')
            
            device.os_info = os_info
            
            # Ports and Services
            tcp_ports = []
            udp_ports = []
            
            for port in root.findall(".//port"):
                port_info = {
                    'number': int(port.get('portid')),
                    'protocol': port.get('protocol'),
                    'state': 'closed'
                }
                
                # Estado del puerto
                state = port.find('state')
                if state is not None:
                    port_info['state'] = state.get('state')
                    if port_info['state'] != 'open':
                        continue
                
                # Información del servicio
                service = port.find('service')
                if service is not None:
                    port_info['name'] = service.get('name', '')
                    port_info['product'] = service.get('product', '')
                    port_info['version'] = service.get('version', '')
                    port_info['extrainfo'] = service.get('extrainfo', '')
                    
                    # Si el servicio es desconocido, intentar identificarlo por el puerto
                    if port_info['name'] in ['unknown', ''] or port_info['name'] is None:
                        common_service = self._get_service_by_port(port_info['number'], port_info['protocol'])
                        if common_service['name'] != 'unknown':
                            port_info['name'] = common_service['name']
                            port_info['product'] = common_service['product']
                            port_info['version'] = common_service['version']
                            if not port_info['extrainfo']:
                                port_info['extrainfo'] = common_service['extrainfo']
                    
                    # Información adicional de scripts
                    scripts = {}
                    for script in port.findall('script'):
                        script_id = script.get('id')
                        if script_id in ['banner', 'http-title', 'ssl-cert', 'http-server-header']:
                            scripts[script_id] = script.get('output', '').strip()
                            
                            # Intentar extraer información del servicio desde el banner
                            if script_id == 'banner' and (not port_info.get('product') or port_info.get('product') == 'unknown'):
                                banner = scripts[script_id].lower()
                                if 'apache' in banner or 'httpd' in banner:
                                    port_info['product'] = 'Apache httpd'
                                elif 'microsoft' in banner and 'iis' in banner:
                                    port_info['product'] = 'Microsoft IIS'
                                elif 'nginx' in banner:
                                    port_info['product'] = 'nginx'
                                elif 'openbsd' in banner and 'openssh' in banner:
                                    port_info['product'] = 'OpenSSH (OpenBSD)'
                    
                    if scripts:
                        port_info['scripts'] = scripts
                
                if port_info['protocol'] == 'tcp':
                    tcp_ports.append(port_info)
                else:
                    udp_ports.append(port_info)
            
            device.tcp_ports = tcp_ports
            device.udp_ports = udp_ports
            
            # Guardar puertos abiertos en formato JSON
            device.open_ports = json.dumps({
                'tcp': [p['number'] for p in tcp_ports],
                'udp': [p['number'] for p in udp_ports]
            })
            
            # Populate the services dictionary for display in the GUI
            for port in tcp_ports:
                port_num = str(port['number'])
                device.services[port_num] = {
                    'name': port.get('name', 'unknown'),
                    'state': port.get('state', 'unknown'),
                    'product': port.get('product', ''),
                    'version': port.get('version', ''),
                    'protocol': 'tcp'
                }
            
            for port in udp_ports:
                port_num = str(port['number'])
                device.services[port_num] = {
                    'name': port.get('name', 'unknown'),
                    'state': port.get('state', 'unknown'),
                    'product': port.get('product', ''),
                    'version': port.get('version', ''),
                    'protocol': 'udp'
                }
            
            # Determinar tipo de dispositivo basado en puertos y OS
            device.determine_device_type()
            
            # Calcular nivel de riesgo basado en puertos y servicios
            risk_score = 0
            high_risk_ports = {21, 22, 23, 445, 3389}  # FTP, SSH, Telnet, SMB, RDP
            medium_risk_ports = {80, 443, 8080, 8443}  # HTTP/HTTPS
            
            for port in tcp_ports:
                port_num = port['number']
                if port_num in high_risk_ports:
                    risk_score += 2
                elif port_num in medium_risk_ports:
                    risk_score += 1
                
                # Verificar servicios vulnerables
                service = port.get('name', '').lower()
                if any(s in service for s in ['telnet', 'ftp', 'rpc']):
                    risk_score += 2
            
            if risk_score > 4:
                device.risk_level = "Alto"
            elif risk_score > 2:
                device.risk_level = "Medio"
            else:
                device.risk_level = "Bajo"
            
            print(f"[DEBUG] Dispositivo {ip_address} - MAC: {device.mac_address or 'No detectada'}, Vendor: {device.vendor or 'Desconocido'}")
            print(f"[DEBUG] Puertos TCP abiertos: {[p['number'] for p in tcp_ports]}")
            print(f"[DEBUG] Puertos UDP abiertos: {[p['number'] for p in udp_ports]}")
            print(f"[DEBUG] Nivel de riesgo: {device.risk_level}")
            
            return device

        except ET.ParseError as e:
            print(f"[ERROR] Error parseando XML del host: {e}")
            return None
        except Exception as e:
            print(f"[ERROR] Error procesando host: {e}")
            import traceback
            traceback.print_exc()
            return None

    def _analyze_unknown_services(self, ip, ports):
        """
        Analyze ports with unknown services using Nmap scripts and version detection.
        
        Args:
            ip (str): Target IP address
            ports (list): List of port dictionaries with port information
            
        Returns:
            list: Updated list of ports with service information
        """
        if not ports:
            return ports
            
        # Filter ports with unknown or empty service names
        unknown_ports = []
        for p in ports:
            port_num = p.get('number')
            service_name = p.get('name', '').lower().strip()
            if not service_name or service_name in ['unknown', '']:
                unknown_ports.append(str(port_num))
        
        if not unknown_ports:
            return ports
            
        print(f"[INFO] Analyzing {len(unknown_ports)} ports with unknown services on {ip}")
        
        try:
            # Build Nmap command with service detection and safe scripts
            command = [
                self.nmap_path,
                '-sV',                  # Version detection
                '--version-intensity', '7',  # Most aggressive version detection
                '--script', 'banner,vulners,safe',  # Safe scripts for service detection
                '--script-args', 'vulners.showall',
                '-Pn',                  # Skip host discovery
                '-n',                   # No DNS resolution
                '-T4',                  # Aggressive timing
                '--max-retries', '3',   # Retry failed ports
                '--host-timeout', '5m', # Max 5 minutes per host
                '-p', ','.join(unknown_ports),
                '-oX', '-',             # XML output to stdout
                '--open',               # Only show open ports
                ip
            ]
            
            # Run Nmap with timeout
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=600,  # 10 minutes max
                encoding='utf-8',
                errors='replace'
            )
            
            if result.returncode != 0:
                print(f"[WARNING] Error analyzing unknown ports: {result.stderr}")
                return ports
                
            # Parse results
            try:
                root = ET.fromstring(result.stdout)
                port_updates = {}
                
                # Process detected services
                for port_elem in root.findall(".//port"):
                    try:
                        port_num = int(port_elem.get('portid'))
                        service = port_elem.find('service')
                        script_outputs = {}
                        
                        # Get script outputs if any
                        for script in port_elem.findall('script'):
                            script_id = script.get('id', '')
                            output = script.get('output', '')
                            if script_id and output:
                                script_outputs[script_id] = output
                        
                        if service is not None:
                            port_updates[port_num] = {
                                'name': service.get('name', '').lower() or 'unknown',
                                'product': service.get('product', ''),
                                'version': service.get('version', ''),
                                'extrainfo': service.get('extrainfo', ''),
                                'scripts': script_outputs or None
                            }
                    except (ValueError, AttributeError) as e:
                        print(f"[WARNING] Error processing port element: {e}")
                        continue
                
                # Update port information
                for port in ports:
                    port_num = port.get('number')
                    if port_num in port_updates:
                        update = port_updates[port_num]
                        port.update({
                            'name': update['name'] or port.get('name', 'unknown'),
                            'product': update['product'] or port.get('product', ''),
                            'version': update['version'] or port.get('version', ''),
                            'extrainfo': update['extrainfo'] or port.get('extrainfo', '')
                        })
                        if update['scripts']:
                            port['scripts'] = update['scripts']
                
            except ET.ParseError as e:
                print(f"[WARNING] Error parsing port analysis results: {e}")
                
        except subprocess.TimeoutExpired:
            print("[WARNING] Timeout while analyzing unknown ports")
        except Exception as e:
            print(f"[WARNING] Unexpected error analyzing unknown ports: {e}")
            import traceback
            traceback.print_exc()
            
        return ports

    def scan(self, target, on_device_found=None):
        """Realiza un escaneo de red mostrando progreso en tiempo real."""
        print(f"[DEBUG] Iniciando escaneo de {target}")  # Debug log
        try:
            # Primero, descubrir hosts activos
            print("[DEBUG] Realizando descubrimiento de hosts...")
            discovery_result = self.quick_scan(target)
            if not discovery_result:
                print("[WARNING] No se encontraron hosts activos")
                return []
                
            # Parsear la salida XML del descubrimiento
            try:
                root = ET.fromstring(discovery_result)
            except ET.ParseError as e:
                print(f"[ERROR] Error al parsear XML de descubrimiento: {e}")
                return []
                
            # Obtener lista de hosts activos
            active_hosts = []
            for host in root.findall(".//host"):
                status = host.find(".//status")
                if status is not None and status.get('state') == 'up':
                    address = host.find(".//address[@addrtype='ipv4']")
                    if address is not None:
                        ip = address.get('addr')
                        if ip and ip not in active_hosts:
                            active_hosts.append(ip)
                            print(f"[INFO] Host activo encontrado: {ip}")
            
            if not active_hosts:
                print("[WARNING] No se encontraron hosts activos")
                return []
                
            # Escanear cada host activo en detalle
            devices = []
            for ip in active_hosts:
                try:
                    print(f"[INFO] Escaneando host {ip}...")
                    device = self.detailed_scan(ip)
                    if device:
                        devices.append(device)
                        print(f"[INFO] Dispositivo encontrado: {device.ip_address} ({device.hostname})")
                        
                        # Llamar al callback si se proporcionó
                        if callable(on_device_found):
                            print(f"[DEBUG] Llamando a on_device_found para {ip}")  # Debug log
                            on_device_found(device)
                    else:
                        print(f"[WARNING] No se pudo escanear el host {ip}")
                        
                except Exception as e:
                    print(f"[ERROR] Error al escanear el host {ip}: {e}")
                    import traceback
                    traceback.print_exc()
            
            print(f"[INFO] Escaneo completado. Se encontraron {len(devices)} dispositivos.")
            return devices
            
        except Exception as e:
            print(f"[ERROR] Error en el escaneo: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _create_device_from_host(self, host, ip_address):
        """Crea un objeto Device a partir de un elemento host XML.
        
        Args:
            host: Elemento XML del host
            ip_address (str): Dirección IP del host
            
        Returns:
            Device: Objeto Device con la información del host o None si hay error
        """
        if not ip_address:
            return None
        
        # Obtener hostname si existe
        hostname_elem = host.find(".//hostname")
        hostname = hostname_elem.get('name') if hostname_elem is not None else ip_address
        
        # Crear dispositivo
        device = Device(ip_address=ip_address, hostname=hostname)
        
        # MAC Address y Vendor
        mac = host.find(".//address[@addrtype='mac']")
        if mac is not None:
            device.mac_address = mac.get('addr')
            device.vendor = mac.get('vendor')
        
        # Establecer estado inicial basado en la respuesta del host
        status = host.find(".//status")
        if status is not None:
            device.status = status.get('state', 'Desconocido').capitalize()
        else:
            device.status = "Activo"  # Asumir que está activo si no se especifica
            
        # OS Detection - Modificado para construir la estructura anidada completa
        parsed_os_info_dict = {}
        os_element = host.find("os") # Encuentra el elemento <os> principal
        
        if os_element is not None:
            osmatches_list = []
            for osmatch_elem in os_element.findall("osmatch"): # Itera sobre todos los <osmatch>
                match_dict = {
                    'name': osmatch_elem.get('name', ''),
                    'accuracy': osmatch_elem.get('accuracy', '0'),
                    # Puedes añadir más atributos de <osmatch> si son necesarios, como 'line'
                    'line': osmatch_elem.get('line', '')
                }
                osclasses_list = []
                for osclass_elem in osmatch_elem.findall("osclass"):
                    class_dict = {
                        'type': osclass_elem.get('type', ''),
                        'vendor': osclass_elem.get('vendor', ''),
                        'osfamily': osclass_elem.get('osfamily', ''),
                        'osgen': osclass_elem.get('osgen', ''),
                        'accuracy': osclass_elem.get('accuracy', '0'),
                    }
                    cpe_list = [cpe.text for cpe in osclass_elem.findall("cpe") if cpe.text]
                    if cpe_list:
                        class_dict['cpe'] = cpe_list # Nmap puede tener múltiples CPEs por osclass
                    osclasses_list.append(class_dict)
                
                if osclasses_list: # Solo añadir el osmatch si tiene al menos un osclass
                    match_dict['osclass'] = osclasses_list
                osmatches_list.append(match_dict)
            
            if osmatches_list:
                parsed_os_info_dict['osmatch'] = osmatches_list
        
        device.os_info = parsed_os_info_dict # Asignar la estructura completa
            
        # Obtener puertos TCP/UDP
        tcp_ports = []
        udp_ports = []
        
        # Primero recopilamos todos los puertos
        for port in host.findall(".//port"):
            port_info = {
                'number': int(port.get('portid')),
                'protocol': port.get('protocol'),
                'state': port.find('state').get('state') if port.find('state') is not None else 'unknown'
            }
            
            # Initialize service-related fields
            service_fields = {
                'name': '',
                'product': '',
                'version': '',
                'extrainfo': '',
                'cpe': ''
            }
            
            service = port.find('service')
            if service is not None:
                # Get service name, using 'name' attribute first, then 'tunnel' if available
                service_name = service.get('name', '').lower()
                if not service_name and 'tunnel' in service.attrib:
                    service_name = service.get('tunnel', '').lower()
                
                # Update service fields
                service_fields.update({
                    'name': service_name or 'unknown',
                    'product': service.get('product', '').strip(),
                    'version': service.get('version', '').strip(),
                    'extrainfo': service.get('extrainfo', '').strip()
                })
                
                # Get CPE if available
                cpe_elem = service.find('cpe')
                if cpe_elem is not None and cpe_elem.text:
                    service_fields['cpe'] = cpe_elem.text.strip()
            
            # Update port_info with service fields
            port_info.update(service_fields)
            
            # Agregar scripts si existen
            scripts = {}
            for script in port.findall('script'):
                scripts[script.get('id')] = script.get('output', '')
            if scripts:
                port_info['scripts'] = scripts
            
            # Add additional service detection logic if needed
            if port_info['state'] == 'open' and not port_info['name']:
                # Try to determine service from port number if Nmap didn't identify it
                if port_info['protocol'] == 'tcp':
                    if port_info['number'] == 135:
                        port_info['name'] = 'msrpc'
                    elif port_info['number'] == 137:
                        port_info['name'] = 'netbios-ns'
                    elif port_info['number'] == 139:
                        port_info['name'] = 'netbios-ssn'
                    elif port_info['number'] == 445:
                        port_info['name'] = 'microsoft-ds'
                    elif port_info['number'] == 5040:
                        port_info['name'] = 'unknown'  # Could be Windows RPC
                    elif port_info['number'] >= 49152:  # Ephemeral ports
                        port_info['name'] = 'unknown'
            
            # Add to appropriate port list
            if port_info['protocol'] == 'tcp':
                tcp_ports.append(port_info)
            else:
                udp_ports.append(port_info)
        
        # Process ports for the device
        for port in tcp_ports + udp_ports:
            port_id = str(port['number'])
            service_info = {
                'port': port_id,
                'protocol': port['protocol'],
                'name': port.get('name', 'unknown'),
                'product': port.get('product', '').strip(),
                'version': port.get('version', '').strip(),
                'extrainfo': port.get('extrainfo', '').strip()
            }
            
            # Clean up service name
            if not service_info['name'] or service_info['name'] == 'unknown':
                # If product is available but name isn't, use product as name
                if service_info['product']:
                    service_info['name'] = service_info['product'].lower()
                else:
                    # For well-known ports, use the standard service name
                    if port['number'] in [135, 137, 139, 445]:
                        known_ports = {135: 'msrpc', 137: 'netbios-ns', 139: 'netbios-ssn', 445: 'microsoft-ds'}
                        service_info['name'] = known_ports[port['number']]
                    else:
                        service_info['name'] = ''  # Empty string will be handled in the display logic
            
            device.services[port_id] = service_info
            
        # Configurar puertos en el dispositivo
        device.tcp_ports = [p for p in tcp_ports if p['state'] == 'open']
        device.udp_ports = [p for p in udp_ports if p['state'] == 'open']
        
        # Configurar puertos abiertos en formato JSON
        open_port_numbers = set()
        if hasattr(device, 'tcp_ports') and device.tcp_ports:
            for p in device.tcp_ports: # device.tcp_ports ya está filtrado por abiertos
                open_port_numbers.add(p['number'])
        if hasattr(device, 'udp_ports') and device.udp_ports:
            for p in device.udp_ports: # device.udp_ports ya está filtrado por abiertos
                open_port_numbers.add(p['number'])
        device.open_ports = sorted(list(open_port_numbers))
        
        # Determinar tipo de dispositivo basado en puertos y OS
        device.determine_device_type()
        
        return device
