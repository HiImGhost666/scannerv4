import sqlite3
import json
import logging # Añadir importación de logging
import time
from typing import Any, List, Dict, Optional

# Imports de tus modelos de datos, tal como los tenías
from miproyectored.model.device import Device
from miproyectored.model.network_report import NetworkReport

# Configurar un logger para este módulo si aún no existe uno a nivel de proyecto
logger = logging.getLogger(__name__) # Puedes usar 'miproyectored.inventory' o similar

class InventoryManager:
    DATABASE_PATH = "network_inventory.db"
    
    def __init__(self):
        self.connection = None
        self._initialize_database()
    
    def _initialize_database(self):
        """Crea las tablas necesarias con la estructura final si no existen."""
        try:
            self.connection = sqlite3.connect(self.DATABASE_PATH)
            cursor = self.connection.cursor()
            
            # Tabla ScanReports
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ScanReports (
                    report_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_target TEXT NOT NULL,
                    scan_timestamp INTEGER NOT NULL,
                    scan_engine_info TEXT
                )
            ''')
            
            # Tabla Devices - ESTRUCTURA FINAL Y MEJORADA
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS Devices (
                    device_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id INTEGER,
                    ip_address TEXT NOT NULL UNIQUE,
                    hostname TEXT,
                    mac_address TEXT,
                    vendor TEXT,
                    os_name TEXT,
                    os_accuracy INTEGER,
                    os_type TEXT,
                    os_vendor TEXT,
                    os_family TEXT,
                    os_gen TEXT,
                    risk_level TEXT,
                    last_scan_timestamp INTEGER,
                    last_scan_success BOOLEAN,
                    last_scan_error TEXT,
                    open_ports TEXT,
                    FOREIGN KEY (report_id) REFERENCES ScanReports(report_id) ON DELETE CASCADE
                )
            ''')
            
            # Tabla DevicePorts
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS DevicePorts (
                    port_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    port_number INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    service_name TEXT,
                    service_product TEXT,
                    service_version TEXT,
                    service_extra_info TEXT,
                    state TEXT NOT NULL,
                    FOREIGN KEY (device_id) REFERENCES Devices(device_id) ON DELETE CASCADE,
                    UNIQUE (device_id, port_number, protocol)
                )
            ''')
            
            # Tablas para datos específicos (WMI, SSH, SNMP)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS WmiData (
                    wmi_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    os_caption TEXT,
                    os_version TEXT,
                    os_architecture TEXT,
                    cpu_name TEXT,
                    cpu_cores TEXT,
                    total_visible_memory_kb TEXT,
                    free_physical_memory_kb TEXT,
                    FOREIGN KEY (device_id) REFERENCES Devices(device_id) ON DELETE CASCADE
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS SshData (
                    ssh_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    os_kernel TEXT,
                    distribution TEXT,
                    uptime TEXT,
                    memory_usage TEXT,
                    disk_usage TEXT,
                    FOREIGN KEY (device_id) REFERENCES Devices(device_id) ON DELETE CASCADE
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS SnmpData (
                    snmp_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    system_name TEXT,
                    system_description TEXT,
                    system_location TEXT,
                    system_contact TEXT,
                    system_uptime TEXT,
                    FOREIGN KEY (device_id) REFERENCES Devices(device_id) ON DELETE CASCADE
                )
            ''')

            self.connection.commit()
            
        except sqlite3.Error as e:
            print(f"Error al inicializar la base de datos: {e}")
            raise

    def save_report(self, report: NetworkReport) -> int:
        """Guarda un reporte de red completo en la base de datos."""
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT INTO ScanReports (scan_target, scan_timestamp, scan_engine_info)
                VALUES (?, ?, ?)
            ''', (report.target, report.scan_timestamp, report.scan_engine_info))
            
            report_id = cursor.lastrowid
            
            for device in report.devices:
                self._save_device(cursor, report_id, device)
            
            self.connection.commit()
            return report_id
            
        except sqlite3.Error as e:
            print(f"Error al guardar reporte: {e}")
            self.connection.rollback()
            raise

    def _save_device(self, cursor, report_id: int, device: Device) -> int:
        """
        Guarda o actualiza un dispositivo, desestructurando correctamente la información del SO
        desde la estructura de datos que provee la librería de escaneo.
        """
        # Log para depuración: ver qué contiene device.os_info
        logger.debug(f"Intentando guardar dispositivo IP: {device.ip_address}. Contenido de device.os_info: {getattr(device, 'os_info', 'No os_info attribute')}")

        # --- INICIO: Lógica de desestructuración del SO (MEJORADA CON FALLBACK) ---
        os_name, os_accuracy, os_type, os_vendor, os_family, os_gen = "Desconocido", 0, "Desconocido", "Desconocido", "Desconocido", "Desconocido"
        
        raw_os_data_dict = getattr(device, 'os_info', None)
        
        parsed_from_nmap_osmatch = False
        if raw_os_data_dict and isinstance(raw_os_data_dict, dict):
            # Primero, intentar parsear la estructura 'osmatch' de Nmap
            os_match_list = raw_os_data_dict.get('osmatch', [])
            if os_match_list and isinstance(os_match_list, list) and len(os_match_list) > 0:
                best_match = os_match_list[0] # Tomar la primera (mejor) coincidencia

                if isinstance(best_match, dict):
                    nmap_os_name_candidate = best_match.get('name')
                    if nmap_os_name_candidate: 
                        os_name = nmap_os_name_candidate
                        parsed_from_nmap_osmatch = True 
                        try:
                            os_accuracy = int(best_match.get('accuracy', '0'))
                        except (ValueError, TypeError):
                            os_accuracy = 0
                        
                        os_class_list = best_match.get('osclass', [])
                        if os_class_list and isinstance(os_class_list, list) and len(os_class_list) > 0:
                            os_class_data = os_class_list[0] 
                            if isinstance(os_class_data, dict):
                                os_type = os_class_data.get('type', os_type)
                                os_vendor = os_class_data.get('vendor', os_vendor) 
                                os_family = os_class_data.get('osfamily', os_family)
                                os_gen = os_class_data.get('osgen', os_gen)
            
            # Fallback si no se parseó de 'osmatch' o si campos clave siguen "Desconocido"
            if not parsed_from_nmap_osmatch or os_name == "Desconocido":
                if os_name == "Desconocido":
                    os_name = raw_os_data_dict.get('name', 
                              raw_os_data_dict.get('caption', 
                              raw_os_data_dict.get('distribution', 
                              raw_os_data_dict.get('description_snmp', 
                              raw_os_data_dict.get('kernel', "Desconocido")))))

                # Si Nmap no dio estos detalles, intentar obtenerlos de claves directas
                if os_type == "Desconocido":
                    os_type = raw_os_data_dict.get('type', "Desconocido")
                
                if os_vendor == "Desconocido": # os_vendor es el fabricante del SO
                    os_vendor = raw_os_data_dict.get('vendor', "Desconocido")

                if os_family == "Desconocido":
                    os_family = raw_os_data_dict.get('osfamily', "Desconocido")

                if os_gen == "Desconocido":
                    os_gen = raw_os_data_dict.get('osgen', "Desconocido")
                
                # os_accuracy es específico de Nmap osmatch.
                # Si no se parseó de osmatch, intentar obtener 'accuracy' del diccionario plano.
                if not parsed_from_nmap_osmatch:
                    try:
                        os_accuracy = int(raw_os_data_dict.get('accuracy', 0))
                    except (ValueError, TypeError):
                        os_accuracy = 0

            # Asegurarse de que os_name no sea None si los fallbacks no encontraron nada
            if os_name is None: os_name = "Desconocido"

        # --- FIN: Lógica de desestructuración del SO ---

        cursor.execute('''
            INSERT INTO Devices (
                report_id, ip_address, hostname, mac_address, vendor,
                os_name, os_accuracy, os_type, os_vendor, os_family, os_gen,
                risk_level, last_scan_timestamp, last_scan_success, last_scan_error,
                open_ports
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                report_id=excluded.report_id, hostname=excluded.hostname, mac_address=excluded.mac_address,
                vendor=excluded.vendor, os_name=excluded.os_name, os_accuracy=excluded.os_accuracy,
                os_type=excluded.os_type, os_vendor=excluded.os_vendor, os_family=excluded.os_family,
                os_gen=excluded.os_gen, risk_level=excluded.risk_level,
                last_scan_timestamp=excluded.last_scan_timestamp,
                last_scan_success=excluded.last_scan_success, last_scan_error=excluded.last_scan_error,
                open_ports=excluded.open_ports
        ''', (
            report_id, device.ip_address, device.hostname, device.mac_address, device.vendor,
            os_name, os_accuracy, os_type, os_vendor, os_family, os_gen,
            getattr(device, 'risk_level', 'Desconocido'),
            getattr(device, 'last_scan_timestamp', int(time.time())),
            getattr(device, 'last_scan_success', True),
            getattr(device, 'scan_error', None),
            json.dumps(getattr(device, 'open_ports', None))
        ))
        
        cursor.execute('SELECT device_id FROM Devices WHERE ip_address = ?', (device.ip_address,))
        device_id = cursor.fetchone()[0]

        cursor.execute('DELETE FROM DevicePorts WHERE device_id = ?', (device_id,))
        
        all_ports = getattr(device, 'tcp_ports', []) + getattr(device, 'udp_ports', [])
        for port_data in all_ports:
            port_detail_to_save = {
                'number': port_data.get('number'),
                'protocol': port_data.get('protocol'),
                'name': port_data.get('name', ''),
                'product': port_data.get('product', ''),
                'version': port_data.get('version', ''),
                'extrainfo': port_data.get('extrainfo', ''),
                'state': port_data.get('state', 'unknown')
            }
            self._save_device_port(cursor, device_id, port_detail_to_save)
        
        if hasattr(device, 'wmi_specific_info') and device.wmi_specific_info:
            self._save_wmi_data(cursor, device_id, device.wmi_specific_info)
        if hasattr(device, 'ssh_specific_info') and device.ssh_specific_info:
            self._save_ssh_data(cursor, device_id, device.ssh_specific_info)
        if hasattr(device, 'snmp_info') and device.snmp_info:
            self._save_snmp_data(cursor, device_id, device.snmp_info)
            
        return device_id

    def _save_device_port(self, cursor, device_id: int, port_details: Dict) -> int:
        """Guarda un puerto de dispositivo en la base de datos."""
        cursor.execute('''
            INSERT INTO DevicePorts (
                device_id, port_number, protocol, service_name, service_product,
                service_version, service_extra_info, state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            device_id, port_details.get('number'), port_details.get('protocol'),
            port_details.get('name'), port_details.get('product'),
            port_details.get('version'), port_details.get('extrainfo'),
            port_details.get('state')
        ))
        return cursor.lastrowid

    def get_reports(self) -> List[Dict]:
        """Obtiene todos los reportes de escaneo como una lista de diccionarios."""
        try:
            cursor = self.connection.cursor()
            cursor.execute('SELECT * FROM ScanReports ORDER BY scan_timestamp DESC')
            columns = [description[0] for description in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except sqlite3.Error as e:
            print(f"Error al obtener reportes: {e}")
            return []

    def close(self):
        """Cierra la conexión a la base de datos si está abierta."""
        if self.connection:
            self.connection.close()
            self.connection = None
    
    def _save_wmi_data(self, cursor, device_id: int, wmi_data: Dict[str, Any]):
        """Guarda datos WMI en la base de datos."""
        cursor.execute('''
            INSERT INTO WmiData (
                device_id, os_caption, os_version, os_architecture,
                cpu_name, cpu_cores, total_visible_memory_kb, free_physical_memory_kb
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            device_id,
            wmi_data.get("os_caption"), wmi_data.get("os_version"),
            wmi_data.get("os_architecture"), wmi_data.get("cpu_name"),
            wmi_data.get("cpu_cores"), wmi_data.get("total_visible_memory_kb"),
            wmi_data.get("free_physical_memory_kb")
        ))

    def _save_ssh_data(self, cursor, device_id: int, ssh_data: Dict[str, Any]):
        """Guarda datos SSH en la base de datos."""
        cursor.execute('''
            INSERT INTO SshData (
                device_id, os_kernel, distribution, uptime,
                memory_usage, disk_usage
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            device_id,
            ssh_data.get("os_kernel"), ssh_data.get("distribution"),
            ssh_data.get("uptime"), ssh_data.get("memory_usage"),
            ssh_data.get("disk_usage")
        ))
    
    def _save_snmp_data(self, cursor, device_id: int, snmp_data: Dict[str, Any]):
        """Guarda datos SNMP en la base de datos."""
        cursor.execute('''
            INSERT INTO SnmpData (
                device_id, system_name, system_description,
                system_location, system_contact, system_uptime
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            device_id,
            snmp_data.get("sysName"), snmp_data.get("sysDescr"),
            snmp_data.get("sysLocation"), snmp_data.get("sysContact"),
            snmp_data.get("sysUpTime")
        ))