import logging
import time
import socket
from typing import Dict, Optional, Any, List, Tuple
import struct
import binascii

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import scapy for SNMP functionality
try:
    from scapy.all import SNMP, SNMPget, SNMPvarbind, ASN1_OID, ASN1_NULL, UDP, IP, sr1
    SNMP_AVAILABLE = True
except ImportError as e:
    SNMP_AVAILABLE = False
    logger.warning(f"Módulo Scapy no disponible. Error: {str(e)}. La funcionalidad SNMP estará deshabilitada.")

class SNMPClient:
    """Cliente para recolectar información mediante SNMP utilizando Scapy."""
    
    def __init__(self, host: str, community: str = "public", port: int = 161, timeout: int = 5):
        self.host = host
        self.community = community
        self.port = port
        self.timeout = timeout
        
    def collect_system_info(self) -> Dict[str, Any]:
        """Recolecta información del sistema mediante SNMP."""
        result = {}
        
        if not SNMP_AVAILABLE:
            result["error"] = "Módulo SNMP no disponible. La funcionalidad SNMP está deshabilitada."
            return result
            
        try:
            # Información básica del sistema
            system_info = self._get_system_info()
            result.update(system_info)
            
            # Información de interfaces de red
            interfaces_info = self._get_interfaces_info()
            result.update(interfaces_info)
            
        except Exception as e:
            error_msg = f"Error al recolectar información SNMP: {str(e)}"
            logger.error(error_msg)
            result["error"] = error_msg
        
        return result
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Obtiene información básica del sistema."""
        result = {}
        
        # OIDs estándar para información del sistema
        oids = {
            "sysDescr": "1.3.6.1.2.1.1.1.0",      # Descripción del sistema
            "sysObjectID": "1.3.6.1.2.1.1.2.0",   # ID del objeto
            "sysUpTime": "1.3.6.1.2.1.1.3.0",     # Tiempo de actividad
            "sysContact": "1.3.6.1.2.1.1.4.0",    # Contacto
            "sysName": "1.3.6.1.2.1.1.5.0",       # Nombre del sistema
            "sysLocation": "1.3.6.1.2.1.1.6.0",   # Ubicación
            "sysServices": "1.3.6.1.2.1.1.7.0"    # Servicios
        }
        
        for name, oid in oids.items():
            value = self._get_snmp_value(oid)
            if value is not None:
                result[name] = value
        
        # Extraer información del sistema operativo de la descripción
        if "sysDescr" in result:
            desc = result["sysDescr"].lower()
            if "windows" in desc:
                result["osType"] = "Windows"
                # Intentar extraer la versión de Windows
                if "windows 10" in desc:
                    result["osName"] = "Windows 10"
                elif "windows server" in desc:
                    result["osName"] = "Windows Server"
                else:
                    result["osName"] = "Windows"
            elif "linux" in desc:
                result["osType"] = "Linux"
                # Intentar extraer la distribución
                for distro in ["ubuntu", "debian", "centos", "redhat", "fedora"]:
                    if distro in desc:
                        result["osName"] = distro.capitalize()
                        break
                else:
                    result["osName"] = "Linux"
            elif "cisco" in desc:
                result["osType"] = "Network Device"
                result["osName"] = "Cisco IOS"
                result["manufacturer"] = "Cisco Systems"
            elif "juniper" in desc:
                result["osType"] = "Network Device"
                result["osName"] = "Juniper"
                result["manufacturer"] = "Juniper Networks"
            elif "fortinet" in desc or "fortigate" in desc:
                result["osType"] = "Firewall"
                result["osName"] = "FortiOS"
                result["manufacturer"] = "Fortinet"
        
        return result
    
    def _get_interfaces_info(self) -> Dict[str, Any]:
        """Obtiene información de interfaces de red."""
        result = {}
        interfaces = []
        
        # OID base para la tabla de interfaces
        if_table_base = "1.3.6.1.2.1.2.2.1"
        
        # OIDs para información de interfaces
        if_index_oid = f"{if_table_base}.1"  # ifIndex
        if_descr_oid = f"{if_table_base}.2"  # ifDescr
        if_type_oid = f"{if_table_base}.3"   # ifType
        if_phys_addr_oid = f"{if_table_base}.6"  # ifPhysAddress (MAC)
        if_oper_status_oid = f"{if_table_base}.8"  # ifOperStatus
        
        # Obtener índices de interfaces
        if_indices = self._get_table_indices(if_index_oid)
        
        for idx in if_indices:
            interface = {}
            
            # Obtener descripción de la interfaz
            if_descr = self._get_snmp_value(f"{if_descr_oid}.{idx}")
            if if_descr:
                interface["description"] = if_descr
            
            # Obtener tipo de interfaz
            if_type = self._get_snmp_value(f"{if_type_oid}.{idx}")
            if if_type:
                interface["type"] = if_type
            
            # Obtener dirección MAC
            if_phys_addr = self._get_snmp_value(f"{if_phys_addr_oid}.{idx}")
            if if_phys_addr and if_phys_addr != "":
                # Convertir la dirección física a formato MAC
                try:
                    # Formatear como dirección MAC
                    mac_addr = self._format_mac_address(if_phys_addr)
                    interface["mac_address"] = mac_addr
                except Exception as e:
                    logger.error(f"Error al convertir dirección física a MAC: {e}")
                    interface["physical_address"] = if_phys_addr
            
            # Obtener estado operativo
            if_oper_status = self._get_snmp_value(f"{if_oper_status_oid}.{idx}")
            if if_oper_status:
                interface["oper_status"] = "up" if if_oper_status == "1" else "down"
            
            # Obtener direcciones IP para esta interfaz
            interface["ip_addresses"] = self._get_ip_addresses_for_interface(idx)
            
            interfaces.append(interface)
        
        # Filtrar interfaces sin dirección MAC o con MAC inválida
        valid_interfaces = [
            intf for intf in interfaces 
            if "mac_address" in intf and 
            intf["mac_address"] != "00:00:00:00:00:00" and
            len(intf["mac_address"]) == 17  # Formato MAC válido: xx:xx:xx:xx:xx:xx
        ]
        
        # Si hay interfaces válidas, tomar la primera MAC como principal
        if valid_interfaces:
            # Priorizar interfaces con IP y estado operativo "up"
            active_interfaces = [
                intf for intf in valid_interfaces
                if intf.get("oper_status") == "up" and intf.get("ip_addresses")
            ]
            
            if active_interfaces:
                result["primaryInterface"] = active_interfaces[0]
                result["macAddress"] = active_interfaces[0]["mac_address"]
            else:
                result["primaryInterface"] = valid_interfaces[0]
                result["macAddress"] = valid_interfaces[0]["mac_address"]
        
        result["interfaces"] = interfaces
        return result
    
    def _get_ip_addresses_for_interface(self, if_index: str) -> list:
        """Obtiene las direcciones IP asociadas a una interfaz."""
        ip_addresses = []
        
        # OID base para la tabla de direcciones IP
        ip_addr_table_base = "1.3.6.1.2.1.4.20.1"
        
        # OID para la dirección IP
        ip_addr_oid = f"{ip_addr_table_base}.1"
        
        # OID para el índice de interfaz
        ip_if_index_oid = f"{ip_addr_table_base}.2"
        
        # Obtener todas las direcciones IP
        ip_entries = self._get_table_column_values(ip_addr_oid)
        
        for ip_entry in ip_entries:
            ip_addr = ip_entry[0]  # La dirección IP está en el OID
            ip_value = ip_entry[1]  # El valor (que es la misma dirección IP)
            
            # Obtener el índice de interfaz para esta dirección IP
            ip_if_idx = self._get_snmp_value(f"{ip_if_index_oid}.{ip_value}")
            
            if ip_if_idx == str(if_index):
                ip_addresses.append(ip_value)
        
        return ip_addresses
    
    def _format_mac_address(self, mac_bytes: str) -> str:
        """Formatea una dirección MAC desde bytes a formato xx:xx:xx:xx:xx:xx."""
        try:
            # Si es una cadena hexadecimal
            if isinstance(mac_bytes, str) and mac_bytes.startswith("0x"):
                hex_str = mac_bytes[2:]
                mac_bytes = bytes.fromhex(hex_str)
            elif isinstance(mac_bytes, str) and all(c in "0123456789abcdefABCDEF:" for c in mac_bytes):
                # Ya está en formato MAC
                return mac_bytes.lower()
            
            # Convertir a bytes si es necesario
            if isinstance(mac_bytes, str):
                mac_bytes = bytes([ord(c) for c in mac_bytes])
                
            # Formatear como dirección MAC
            return ':'.join(f'{b:02x}' for b in mac_bytes)
        except Exception as e:
            logger.error(f"Error formateando MAC: {e}")
            return "00:00:00:00:00:00"
    
    def _get_table_indices(self, oid: str) -> list:
        """Obtiene los índices de una tabla SNMP."""
        indices = []
        
        try:
            # Obtener los valores de la columna
            column_values = self._get_table_column_values(oid)
            
            # Extraer los índices
            for entry in column_values:
                index = entry[0]
                indices.append(index)
                
        except Exception as e:
            logger.error(f"Error al obtener índices de tabla SNMP para OID {oid}: {e}")
        
        return indices
    
    def _get_table_column_values(self, oid: str) -> List[Tuple[str, str]]:
        """Obtiene los valores de una columna de tabla SNMP junto con sus OIDs."""
        results = []
        
        try:
            # Crear un paquete SNMP GetNext
            packet = IP(dst=self.host)/UDP(sport=0, dport=self.port)/SNMP(
                community=self.community,
                PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid), value=ASN1_NULL())])
            )
            
            # Enviar el paquete y recibir la respuesta
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response and SNMP in response:
                # Procesar la respuesta
                snmp_response = response[SNMP]
                
                # Extraer los valores
                for varbind in snmp_response.PDU.varbindlist:
                    oid_str = str(varbind.oid)
                    value = str(varbind.value)
                    
                    # Extraer el índice/sufijo del OID
                    suffix = oid_str[len(oid)+1:]
                    results.append((suffix, value))
                    
        except Exception as e:
            logger.error(f"Error al obtener valores de columna SNMP para OID {oid}: {e}")
        
        return results
    
    def _get_snmp_value(self, oid: str) -> Optional[str]:
        """Obtiene un valor SNMP para un OID específico."""
        try:
            # Crear un paquete SNMP Get
            packet = IP(dst=self.host)/UDP(sport=0, dport=self.port)/SNMP(
                community=self.community,
                PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid), value=ASN1_NULL())])
            )
            
            # Enviar el paquete y recibir la respuesta
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response and SNMP in response:
                # Procesar la respuesta
                snmp_response = response[SNMP]
                
                # Extraer el valor
                if len(snmp_response.PDU.varbindlist) > 0:
                    return str(snmp_response.PDU.varbindlist[0].value)
                    
        except Exception as e:
            logger.error(f"Error al obtener valor SNMP para OID {oid}: {e}")
            
        return None