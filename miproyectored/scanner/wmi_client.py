from typing import Dict, Optional
import logging # Añadido para logging

# Necesitarás instalar la librería wmi: pip install wmi
# Esta librería es específica para Windows.
try:
    import wmi
except ImportError:
    # Registrar el error en lugar de imprimirlo directamente si el logger ya está configurado
    logging.getLogger(__name__).error("Librería 'wmi' no encontrada. Este módulo solo funcionará en Windows con 'wmi' instalado.")
    logging.getLogger(__name__).error("Puedes instalarla con: pip install wmi")
    wmi = None

class WmiClient:
    def __init__(self, host: str, username: Optional[str] = None, password: Optional[str] = None, domain: Optional[str] = None):
        self.host = host
        self.username = username
        self.password = password
        self.domain = domain
        self.connection = None
        self.connection_error: Optional[str] = None # Añadido

        logger = logging.getLogger(__name__) # Usar logger específico del módulo
        if not wmi:
            self.connection_error = "Librería 'wmi' no disponible."
            logger.error(self.connection_error + " WmiClient no funcionará.")
            return

        try:
            user_connect = self.username
            if self.domain and self.username and '\\' not in self.username:
                # WMI a menudo requiere el formato DOMINIO\usuario para conexiones remotas autenticadas
                user_connect = f"{self.domain}\\{self.username}"

            if host.lower() == "localhost" or host == "127.0.0.1":
                if user_connect: # Si se proveen credenciales para localhost, usarlas
                     logger.info(f"Intentando conectar a WMI localmente en {self.host} con usuario {user_connect}...")
                     self.connection = wmi.WMI(computer=self.host, user=user_connect, password=self.password)
                else: # Conexión local sin credenciales explícitas
                    logger.info(f"Intentando conectar a WMI localmente en {self.host} sin credenciales explícitas...")
                    self.connection = wmi.WMI() # Conexión local
            else:
                # Conexión remota
                if not user_connect or not self.password:
                    self.connection_error = f"Credenciales (usuario/contraseña) incompletas para conexión WMI remota a {self.host}."
                    logger.warning(self.connection_error)
                    return # Salir si no hay credenciales para host remoto

                logger.info(f"Intentando conectar a WMI en {self.host} con usuario {user_connect}...")
                self.connection = wmi.WMI(computer=self.host, user=user_connect, password=self.password)
            
            # Realizar una consulta simple para verificar la conexión
            _ = self.connection.Win32_OperatingSystem()[0] 
            logger.info(f"Conexión WMI a {self.host} exitosa.")

        except wmi.x_wmi as e:
            self.connection_error = f"Error WMI al conectar a {self.host}: {e}"
            # Analizar 'e' para un mensaje más específico sobre permisos
            if hasattr(e, 'com_error') and hasattr(e.com_error, 'hresult'):
                # HRESULT 0x80070005 es Access Denied
                if e.com_error.hresult == -2147024891: # 0x80070005
                    self.connection_error += " (Acceso Denegado - verificar permisos y credenciales WMI remotas, y configuración del firewall)"
            logger.warning(self.connection_error)
            logger.warning("Asegúrate de que el servicio WMI esté corriendo, el firewall lo permita, y las credenciales sean correctas.")
            self.connection = None
        except IndexError: # Si la consulta de verificación no devuelve nada
            self.connection_error = f"Error WMI: La consulta de verificación no devolvió resultados en {self.host}."
            logger.warning(self.connection_error)
            self.connection = None
        except Exception as e:
            self.connection_error = f"Error inesperado al inicializar WMI para {self.host}: {e}"
            logger.error(self.connection_error, exc_info=True)
            self.connection = None

        logger = logging.getLogger(__name__) # Asegurar que logger esté definido para el método

    def collect_system_info(self) -> Dict[str, str]:
        info: Dict[str, str] = {}
        if self.connection_error: # Comprobar primero el error de conexión de __init__
            info["error"] = self.connection_error
            return info
        if not self.connection: # Si no hubo error en init pero la conexión es None (caso improbable si init se corrige)
            info["error"] = "No se pudo establecer la conexión WMI (conexión es None)."
            return info

        logger = logging.getLogger(__name__) # Asegurar que logger esté definido

        try:
            # Información del Sistema Operativo
            os_info_list = self.connection.Win32_OperatingSystem()
            if os_info_list:
                os_info = os_info_list[0]
                info["os_caption"] = str(os_info.Caption)
                info["os_version"] = str(os_info.Version)
                info["os_architecture"] = str(os_info.OSArchitecture)
                info["system_directory"] = str(os_info.SystemDirectory)
                info["free_physical_memory_kb"] = str(os_info.FreePhysicalMemory)
                info["total_visible_memory_kb"] = str(os_info.TotalVisibleMemorySize)
            else:
                info["os_info_error"] = "No se pudo obtener información del Sistema Operativo."

            # Información del Procesador
            cpu_info_list = self.connection.Win32_Processor()
            if cpu_info_list:
                cpu_info = cpu_info_list[0] # Asumimos un solo procesador para simplificar, podría haber múltiples sockets
                info["cpu_name"] = str(cpu_info.Name)
                info["cpu_manufacturer"] = str(cpu_info.Manufacturer)
                info["cpu_max_clock_speed_mhz"] = str(cpu_info.MaxClockSpeed)
                info["cpu_cores"] = str(cpu_info.NumberOfCores)
                info["cpu_logical_processors"] = str(cpu_info.NumberOfLogicalProcessors)
            else:
                info["cpu_info_error"] = "No se pudo obtener información del Procesador."

            # Información de Discos Lógicos
            logical_disks = self.connection.Win32_LogicalDisk(DriveType=3) # DriveType 3 son discos fijos
            if logical_disks:
                for i, disk in enumerate(logical_disks):
                    info[f"disk_{i}_device_id"] = str(disk.DeviceID)
                    info[f"disk_{i}_total_gb"] = str(int(disk.Size or 0) // (1024**3))
                    info[f"disk_{i}_free_gb"] = str(int(disk.FreeSpace or 0) // (1024**3))
                    info[f"disk_{i}_filesystem"] = str(disk.FileSystem)
                    info[f"disk_{i}_volume_name"] = str(disk.VolumeName) if disk.VolumeName else "N/A"
            else:
                info["logical_disks_status"] = "No se encontraron discos fijos."
            
            # Información de Red (más granular)
            net_adapters = self.connection.Win32_NetworkAdapterConfiguration(IPEnabled=True)
            if net_adapters:
                # Iterar sobre todos los adaptadores con IP habilitada o tomar el primero/principal
                # Aquí tomaremos el primero como ejemplo, pero podrías querer iterar y prefijar por adaptador_idx
                adapter = net_adapters[0] 
                info["network_adapter_0_description"] = str(adapter.Description)
                
                if adapter.IPAddress:
                    for i, ip_addr in enumerate(adapter.IPAddress):
                        info[f"network_adapter_0_ip_address_{i}"] = str(ip_addr)
                else:
                    info["network_adapter_0_ip_addresses"] = "N/A"

                info["network_adapter_0_mac_address"] = str(adapter.MACAddress)

                if adapter.DefaultIPGateway:
                    for i, gw in enumerate(adapter.DefaultIPGateway):
                        info[f"network_adapter_0_default_gateway_{i}"] = str(gw)
                else:
                    info["network_adapter_0_default_gateways"] = "N/A"

                if adapter.DNSServerSearchOrder:
                    for i, dns in enumerate(adapter.DNSServerSearchOrder):
                        info[f"network_adapter_0_dns_server_{i}"] = str(dns)
                else:
                    info["network_adapter_0_dns_servers"] = "N/A"
            else:
                info["network_adapters_status"] = "No se encontraron adaptadores de red con IP habilitada."

            if "error" not in info and not any(key.endswith("_error") for key in info):
                 info["status"] = "Información WMI recolectada exitosamente."
            else:
                 info["status"] = "Información WMI recolectada parcialmente o con errores."


        except wmi.x_wmi as e:
            err_msg = f"Error WMI durante la recolección de datos en {self.host}: {e}"
            if hasattr(e, 'com_error') and hasattr(e.com_error, 'hresult'):
                if e.com_error.hresult == -2147024891: # 0x80070005
                    err_msg += " (Acceso Denegado durante la recolección de datos)"
            logger.warning(err_msg)
            info["error"] = err_msg
        except IndexError:
            # Esto puede pasar si una consulta no devuelve resultados (ej. Win32_Processor() está vacío)
            err_msg = f"Error WMI: Una consulta no devolvió los resultados esperados en {self.host}."
            logger.warning(err_msg)
            info["error"] = err_msg
        except Exception as e:
            err_msg = f"Error inesperado durante la recolección de datos WMI en {self.host}: {e}"
            logger.error(err_msg, exc_info=True)
            info["error"] = err_msg
            
        return info

if __name__ == '__main__':
    # Ejemplo de uso para la máquina local (Windows)
    # if wmi:
    #     print("Probando WMI Client localmente...")
    #     local_client = WmiClient("localhost")
    #     if local_client.connection:
    #         system_data = local_client.collect_system_info()
    #         for key, value in system_data.items():
    #             print(f"{key}: {value}")
    #     else:
    #         print("No se pudo conectar a WMI localmente.")
    # else:
    #     print("La librería WMI no está cargada. No se puede probar WmiClient.")
    print("Descomenta el ejemplo en __main__ para probar WmiClient en una máquina Windows.")
    print("Asegúrate de ejecutar como administrador si tienes problemas de permisos.")