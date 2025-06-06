import logging
import time
import socket
import struct
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
    
    def _is_snmp_error_value(self, value: Any) -> bool:
        """Checks if the SNMP value is a known error indicator."""
        return isinstance(value, (ASN1_NULL, paramiko.asn1.ASN1_NoSuchObject, paramiko.asn1.ASN1_NoSuchInstance, paramiko.asn1.ASN1_EndOfMibView))

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
    
    def _get_ip_addresses_for_interface(self, if_index: str) -> List[str]:
        """Obtiene las direcciones IP asociadas a una interfaz."""
        ip_addresses = []
        
        # OID base para la tabla de direcciones IP
        ip_addr_table_base = "1.3.6.1.2.1.4.20.1"
        
        # OID para la dirección IP
        ip_addr_oid = f"{ip_addr_table_base}.1"
        
        # OID para el índice de interfaz
        ip_if_index_oid = f"{ip_addr_table_base}.2"
        
        # Perform a walk on the ipAdEntIfIndex column
        current_oid = ip_if_index_oid
        while True:
            next_entry = self._get_next_snmp_value(current_oid)
            if next_entry is None:
                break # End of MIB view or error

            next_oid_str, returned_if_index = next_entry

            # Check if the returned OID is still within the ipAdEntIfIndex column subtree
            if not next_oid_str.startswith(ip_if_index_oid):
                break # Walked out of the column

            # The OID format for ipAdEntIfIndex is 1.3.6.1.2.1.4.20.1.2.<ip_address_index>
            # where <ip_address_index> is the IP address itself represented as OID parts (e.g., .192.168.1.10)
            # We need to extract the IP address from the OID.
            try:
                # Find the part of the OID after the column OID
                ip_address_oid_part = next_oid_str[len(ip_if_index_oid):]
                # Remove the leading dot
                if ip_address_oid_part.startswith('.'):
                    ip_address_oid_part = ip_address_oid_part[1:]

                # Check if the returned ifIndex matches the target if_index
                if returned_if_index == str(if_index):
                    # The IP address is the part of the OID after the column OID
                    # Reconstruct the IP address string
                    ip_address_parts = ip_address_oid_part.split('.')
                    if len(ip_address_parts) == 4:
                         ip_address_str = ".".join(ip_address_parts)
                         ip_addresses.append(ip_address_str)
                    else:
                         logger.warning(f"Unexpected IP address format in OID part: {ip_address_oid_part}")

            except Exception as e:
                logger.warning(f"Error extracting IP address from OID {next_oid_str}: {e}")
                # If we can't parse the IP, stop the walk
                break

            # Set the current OID for the next iteration to the OID of the returned value
            current_oid = next_oid_str

        return ip_addresses

    def _format_mac_address(self, mac_bytes: str) -> str:
        """Formatea una dirección MAC desde bytes a formato xx:xx:xx:xx:xx:xx."""
        # Scapy often returns MAC addresses as bytes or a string representation of bytes
        # Let's try to handle common cases
        try:
            # If it's already a colon-separated string, normalize it
            if isinstance(mac_bytes, str) and self._is_valid_mac_address_format(mac_bytes):
                return mac_bytes.lower()

            # If it's a hex string (e.g., from Nmap scripts sometimes)
            if isinstance(mac_bytes, str) and re.match(r'^[0-9A-Fa-f]{12}$', mac_bytes):
                 return ':'.join(mac_bytes[i:i+2] for i in range(0, 12, 2)).lower()

            # If it's a byte string (common in SNMP responses)
            if isinstance(mac_bytes, (bytes, bytearray)):
                 return ':'.join(f'{b:02x}' for b in mac_bytes).lower()

            # If it's a string representation of bytes (e.g., "b'\x00\x1a+<binary data>'")
            if isinstance(mac_bytes, str) and mac_bytes.startswith("b'"):
                 # This is tricky, might need eval or careful parsing depending on the exact string format
                 # A safer approach is to try converting the string to bytes directly
                 try:
                     byte_representation = eval(mac_bytes) # Use eval cautiously, or parse manually
                     if isinstance(byte_representation, bytes):
                         return ':'.join(f'{b:02x}' for b in byte_representation).lower()
                 except Exception:
                     pass # Fallback to other methods

            # If it's a string like "0x1a2b3c4d5e6f"
            if isinstance(mac_bytes, str) and mac_bytes.startswith("0x"):
                 hex_str = mac_bytes[2:]
                 if re.match(r'^[0-9A-Fa-f]+$', hex_str):
                     # Pad with leading zeros if necessary to make it an even length
                     if len(hex_str) % 2 != 0:
                         hex_str = '0' + hex_str
                     return ':'.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2)).lower()

            # If none of the above, return a default invalid MAC
            logger.warning(f"Could not format MAC address from unexpected type/format: {type(mac_bytes)} - {mac_bytes}")
            return "00:00:00:00:00:00"

        except Exception as e:
            logger.error(f"Error formatting MAC: {e}")
            return "00:00:00:00:00:00"

    def _is_valid_mac_address_format(self, mac_address: str) -> bool:
        """Checks if a string is in a common MAC address format."""
        # Formats like AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF
        return bool(re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', mac_address))

    def _get_table_indices(self, oid: str) -> List[str]:
        """Obtiene los índices de una tabla SNMP realizando un walk."""
        indices = []
        current_oid = oid
        try:
            while True:
                next_entry = self._get_next_snmp_value(current_oid)
                if next_entry is None:
                    break # End of MIB view or error

                next_oid_str, value = next_entry

                # Check if the returned OID is still within the table's subtree
                # The returned OID should start with the table's base OID
                if not next_oid_str.startswith(oid):
                    break # Walked out of the table

                # Extract the index from the returned OID
                # The OID format for a table entry is OID.index1.index2...
                # For a simple table like ifTable, it's OID.ifIndex
                # So, we need the part after the column OID (e.g., 1.3.6.1.2.1.2.2.1.1)
                # and before the index (e.g., .1, .2, .3)
                # The returned OID will be like 1.3.6.1.2.1.2.2.1.1.1, 1.3.6.1.2.1.2.2.1.1.2, etc.
                # We need to extract the last part (1, 2, etc.)
                try:
                    # Find the part of the OID after the column OID
                    index_part = next_oid_str[len(oid):]
                    # Remove the leading dot
                    if index_part.startswith('.'):
                        index_part = index_part[1:]

                    # For ifTable (1.3.6.1.2.1.2.2.1), the index is just the ifIndex (e.g., .1, .2)
                    # So the returned OID for ifIndex.1 is 1.3.6.1.2.1.2.2.1.1.1
                    # We need to extract the last '1'.
                    # Let's split by '.' and take the first element after the column OID.
                    # This assumes a simple index structure like OID.column.index
                    index_parts = index_part.split('.')
                    if index_parts:
                        index = index_parts[0] # Assuming the first part after the column OID is the index
                        if index and index.isdigit(): # Ensure index is numeric
                            indices.append(index)

                except Exception as e:
                    logger.warning(f"Error extracting index from OID {next_oid_str}: {e}")
                    # If we can't parse the index, stop the walk to avoid infinite loops
                    break

                # Set the current OID for the next iteration to the OID of the returned value
                current_oid = next_oid_str

        except Exception as e:
            logger.error(f"Error durante el walk SNMP para OID {oid}: {e}")

        # Remove duplicates and sort
        return sorted(list(set(indices)), key=int)

    def _get_next_snmp_value(self, oid: str) -> Optional[Tuple[str, Any]]:
        """Gets the next value in the MIB tree after the given OID."""
        try:
            # Create an SNMP GetNext packet
            packet = IP(dst=self.host)/UDP(sport=0, dport=self.port)/SNMP(
                community=self.community,
                PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid), value=ASN1_NULL())])
            )

            # Send the packet and receive the response
            response = sr1(packet, timeout=self.timeout, verbose=0)

            if response and SNMP in response:
                # Process the response
                snmp_response = response[SNMP]

                # Extract the value
                if len(snmp_response.PDU.varbindlist) > 0:
                    varbind = snmp_response.PDU.varbindlist[0]
                    # Check the type of the value
                    if self._is_snmp_error_value(varbind.value):
                         logger.debug(f"SNMP GETNEXT for OID {oid} returned special value: {type(varbind.value).__name__}")
                         return None # End of walk or error
                    else:
                        # Return the OID of the returned value and the value itself
                        # Need to handle different value types (string, integer, bytes, etc.)
                        value = varbind.value
                        if isinstance(value, (bytes, bytearray)):
                             # Attempt to decode bytes, fallback to hex string if fails
                             try:
                                 value_str = value.decode('utf-8')
                             except UnicodeDecodeError:
                                 value_str = binascii.hexlify(value).decode('utf-8')
                        else:
                             value_str = str(value)

                        return (str(varbind.oid), value_str)

        except Exception as e:
            logger.error(f"Error al obtener siguiente valor SNMP para OID {oid}: {e}")

        return None

    def _get_snmp_value(self, oid: str) -> Optional[str]:
        """Obtiene un valor SNMP para un OID específico."""
        try:
            # Create an SNMP Get packet
            packet = IP(dst=self.host)/UDP(sport=0, dport=self.port)/SNMP(
                community=self.community,
                PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid), value=ASN1_NULL())])
            )

            # Send the packet and receive the response
            response = sr1(packet, timeout=self.timeout, verbose=0)

            if response and SNMP in response:
                # Process the response
                snmp_response = response[SNMP]

                # Extract the value
                if len(snmp_response.PDU.varbindlist) > 0:
                    varbind = snmp_response.PDU.varbindlist[0]
                    # Check the type of the value
                    if self._is_snmp_error_value(varbind.value):
                         logger.debug(f"SNMP GET for OID {oid} returned special value: {type(varbind.value).__name__}")
                         return None # Or a specific error indicator if needed
                    else:
                        value = varbind.value
                        if isinstance(value, (bytes, bytearray)):
                             try:
                                 value_str = value.decode('utf-8')
                             except UnicodeDecodeError:
                                 value_str = binascii.hexlify(value).decode('utf-8')
                        else:
                             value_str = str(value)
                        return value_str

        except Exception as e:
            logger.error(f"Error al obtener valor SNMP para OID {oid}: {e}")

        return None

    # Removed _get_table_column_values as it was replaced by _get_next_snmp_value and walk logic
    # def _get_table_column_values(self, oid: str) -> List[Tuple[str, str]]:
    #     """Obtiene los valores de una columna de tabla SNMP junto con sus OIDs."""
    #     results = []
    #
    #     try:
    #         # Crear un paquete SNMP GetNext
    #         packet = IP(dst=self.host)/UDP(sport=0, dport=self.port)/SNMP(
    #             community=self.community,
    #             PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(oid), value=ASN1_NULL())])
    #         )
    #
    #         # Enviar el paquete y recibir la respuesta
    #         response = sr1(packet, timeout=self.timeout, verbose=0)
    #
    #         if response and SNMP in response:
    #             # Procesar la respuesta
    #             snmp_response = response[SNMP]
    #
    #             # Extraer los valores
    #             for varbind in snmp_response.PDU.varbindlist:
    #                 oid_str = str(varbind.oid)
    #                 value = str(varbind.value)
    #
    #                 # Extraer el índice/sufijo del OID
    #                 suffix = oid_str[len(oid)+1:]
    #                 results.append((suffix, value))
    #
    #     except Exception as e:
    #         logger.error(f"Error al obtener valores de columna SNMP para OID {oid}: {e}")
    #
    #     return results

            
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