import logging
from typing import List, Optional

from miproyectored.model.device import Device
from miproyectored.auth.network_credentials import NetworkCredentials
from miproyectored.scanner.snmp_client import SNMPClient, SNMP_AVAILABLE

class SnmpScanner:
    """Escáner SNMP para recolectar información de dispositivos."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        if not SNMP_AVAILABLE:
            self.logger.warning("Módulo SNMP no disponible. La funcionalidad de escaneo SNMP estará deshabilitada.")
    
    def scan_device(self, device: Device, credentials: NetworkCredentials) -> bool:
        """Escanea un dispositivo mediante SNMP y actualiza su información."""
        if not SNMP_AVAILABLE:
            self.logger.warning(f"Escaneo SNMP deshabilitado para {device.ip_address}: Módulo SNMP no disponible")
            device.snmp_info = {"error": "Módulo SNMP no disponible. La funcionalidad SNMP está deshabilitada."}
            return False
        
        self.logger.info(f"Iniciando escaneo SNMP para {device.ip_address}")
        success = False
        
        # Intentar con diferentes comunidades SNMP si no se proporcionan credenciales específicas
        communities = []
        if credentials and credentials.snmp_community:
            communities.append(credentials.snmp_community)
        else:
            # Comunidades SNMP comunes para probar
            communities = ["public", "private", "community"]
        
        for community in communities:
            try:
                client = SNMPClient(host=device.ip_address, community=community)
                system_info = client.collect_system_info()
                
                # Si hay un error en la respuesta SNMP, continuar con la siguiente comunidad
                if "error" in system_info:
                    self.logger.warning(f"Error SNMP para {device.ip_address} con comunidad {community}: {system_info['error']}")
                    continue
                
                # Dejar que el método update_from_snmp del dispositivo maneje la lógica de actualización
                device.update_from_snmp(system_info)
                
                success = True
                self.logger.info(f"Escaneo SNMP exitoso para {device.ip_address} con comunidad {community}")
                break
                
            except Exception as e:
                self.logger.error(f"Error durante el escaneo SNMP de {device.ip_address}: {str(e)}")
        
        if not success:
            error_message_snmp = f"No se pudo obtener información SNMP de {device.ip_address}."
            if communities: # communities se define antes en el bucle
                error_message_snmp += f" Se intentó con las comunidades: {', '.join(communities)}."
            error_message_snmp += " Verificar la configuración SNMP del dispositivo (agente habilitado, versión, ACLs) y las comunidades."
            self.logger.warning(error_message_snmp)
            device.snmp_info = {"error": error_message_snmp}
        
        return success
    
    def scan_devices(self, devices: List[Device], credentials: Optional[NetworkCredentials] = None) -> int:
        """Escanea una lista de dispositivos mediante SNMP.
        
        Args:
            devices: Lista de dispositivos a escanear
            credentials: Credenciales de red a utilizar
            
        Returns:
            Número de dispositivos escaneados con éxito
        """
        if not SNMP_AVAILABLE:
            self.logger.warning("Escaneo SNMP deshabilitado: Módulo SNMP no disponible")
            for device in devices:
                device.snmp_info = {"error": "Módulo SNMP no disponible. La funcionalidad SNMP está deshabilitada."}
            return 0
        
        success_count = 0
        
        for device in devices:
            if self.scan_device(device, credentials):
                success_count += 1
        
        return success_count