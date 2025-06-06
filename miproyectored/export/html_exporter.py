# html_exporter.py
import os
from datetime import datetime
from html import escape # Importación movida al inicio del archivo
from typing import List, Dict, Any, Optional
from miproyectored.model.device import Device # Asegúrate que la importación sea correcta

class HtmlExporter:
    """
    Clase para exportar resultados de escaneo de red a formato HTML
    con información detallada del dispositivo.
    """
    
    def __init__(self):
        # Nota: self.device_template_str_format no se usa activamente.
        # que construye el HTML dinámicamente.

        self.html_template = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Escaneo de Red</title>
    <!-- Estilos para el nuevo encabezado de la empresa -->
    <style>
        .company-header {{
            padding: 10px 20px;
            background-color: #FFFFFF; /* Blanco */
            border-bottom: 1px solid #A6BBC8; /* azul_claro */
            margin-bottom: 20px;
            text-align: left;
        }}
        .company-header img {{
            height: 45px; /* Altura como en app_gui.py */
            width: auto;
        }}
    </style>
    <style>
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #091F2C; /* azul_oscuro */
            max-width: 1200px;
            margin: 20px auto; /* Añadido margen superior/inferior */
            padding: 20px;
            background-color: #f5f7fa;
        }}
        h1, h2, h3 {{
            color: #091F2C; /* azul_oscuro */
            margin-bottom: 15px;
        }}
        .report-header {{
            background-color: #fff;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 20px; /* Reducido para compensar company-header */
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            border-left: 5px solid #C10016; /* rojo */
        }}
        .device-card {{
            background-color: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
            overflow: hidden; /* Importante para que el border-radius afecte a los hijos */
            border: 1px solid #e1e4e8;
        }}
        .device-header {{
            background: linear-gradient(135deg, #7A99AC, #091F2C); /* azul_medio, azul_oscuro */
            color: white;
            padding: 18px 25px;
            /* margin: 0; Ya está reseteado por * */
            font-size: 1.4em;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .device-header small {{
            font-size: 0.7em;
            opacity: 0.9;
            font-weight: normal;
        }}
        .device-content {{
            padding: 25px;
        }}
        .device-section {{
            margin-bottom: 20px; /* Reducido ligeramente */
            background-color: #fdfdfd; /* Un poco más suave que #fff para contraste sutil */
            border-radius: 6px;
            padding: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.04);
            border: 1px solid #eaeef2;
        }}
        .device-section:last-child {{
            margin-bottom: 0; /* Quitar margen inferior del último device-section */
        }}
        .device-section h3 {{
            color: #091F2C; /* azul_oscuro */
            padding-bottom: 10px;
            border-bottom: 2px solid #f0f2f5;
            margin-top: 0; /* Quitar margen superior del h3 dentro de device-section */
            margin-bottom: 20px;
            font-size: 1.2em;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px; /* Ajustado margen */
            margin-bottom: 10px;
            font-size: 0.95em;
        }}
        th, td {{
            border: 1px solid #e1e4e8;
            padding: 10px 12px; /* Ajustado padding */
            text-align: left;
            vertical-align: top; /* Mejor para contenido multilínea */
        }}
        th {{
            background-color: #A6BBC8; /* azul_claro */
            font-weight: 600;
            color: #091F2C; /* azul_oscuro */
        }}
        tr:nth-child(even) td {{ /* Aplicar solo a td para que th mantenga su fondo */
            background-color: #fcfdff; /* Muy sutil */
        }}
        tr:hover td {{ /* Aplicar solo a td */
            background-color: #f1f5f9;
        }}
        .port-open {{ color: #27ae60; font-weight: 600; }}
        .port-closed {{ color: #e74c3c; font-weight: 600; }}
        .port-filtered {{ color: #f39c12; font-weight: 600; }}
        
        .summary-card {{
            background-color: #fff;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-around; /* space-around para mejor distribución */
            flex-wrap: wrap;
            gap: 15px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            border: 1px solid #eaeef2;
        }}
        .summary-item {{
            flex: 1;
            min-width: 150px; /* O ajusta según el número de items */
            max-width: 200px; /* Para evitar que se estiren demasiado */
            background-color: #f8f9fa;
            border-radius: 6px;
            padding: 15px;
            text-align: center;
            border: 1px solid #e9ecef;
            transition: transform 0.2s ease-out, box-shadow 0.2s ease-out;
        }}
        .summary-item:hover {{
            transform: translateY(-3px);
            box-shadow: 0 4px 12px rgba(44, 62, 80, 0.1); /* Sombra más pronunciada */
        }}
        .summary-item h3 {{ /* Estilo del h3 dentro del summary-item */
            margin: 0 0 8px 0;
            color: #5d6778;
            font-size: 0.85em; /* Ligeramente más pequeño */
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .summary-item p {{ /* Estilo del p dentro del summary-item */
            margin: 0;
            font-size: 1.8em;
            font-weight: 700;
            color: #C10016; /* rojo */
        }}
        footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px; /* Solo padding superior */
            color: #7f8c8d;
            font-size: 0.9em;
            border-top: 1px solid #eaeef2;
        }}
        /* Estilos para la lista de puertos */
        .ports-list {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); /* Ajustado para ~4+ por fila, reduciendo tamaño */
            gap: 20px; /* Aumentado el gap */
            margin-top: 15px;
        }}
        .port-block {{
            background: #ffffff;
            border: 1px solid #dde4ea; /* Borde sutil */
            border-radius: 6px;
            overflow: hidden;
            transition: transform 0.2s ease-out, box-shadow 0.2s ease-out;
            /* margin-bottom: 10px; No es necesario si el gap del grid funciona bien */
            /* max-width: 400px; El grid ya maneja el ancho */
        }}
        .port-block:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(44, 62, 80, 0.08);
        }}
        .port-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 15px; /* Ajustado */
            background-color: #f8f9fa;
            border-bottom: 1px solid #e1e4e8;
        }}
        .port-number {{
            font-weight: 600;
            color: #091F2C; /* azul_oscuro */
            font-size: 1em; /* Ajustado */
        }}
        .port-details {{ /* Tabla dentro de cada port-block */
            width: 100%;
            border-collapse: collapse; /* Asegurado */
            font-size: 0.9em; /* Ajustado */
            table-layout: fixed; /* Ayuda a controlar anchos de columna */
        }}
        .port-details th, .port-details td {{
            padding: 8px 12px; /* Ajustado */
            border-bottom: 1px solid #f0f2f5; /* Borde solo inferior para limpieza */
            border-left: none; /* Quitar bordes laterales dentro de la tabla de puerto */
            border-right: none;
            border-top: none;
            text-align: left;
            vertical-align: top;
            word-wrap: break-word; /* Para texto largo */
        }}
        .port-details th {{
            width: 100px; /* Ancho fijo para la cabecera de la propiedad */
            color: #555; /* Un poco más oscuro */
            font-weight: 500;
            background-color: #fdfdfd; /* Fondo muy sutil para el th */
            /* font-size: 0.9em; Hereda de .port-details o ajustar si es necesario */
        }}
        .port-details tr:last-child th,
        .port-details tr:last-child td {{
            border-bottom: none; /* Quitar borde inferior de la última fila */
        }}
        .error {{ /* Clase para mensajes de error */
            color: #e74c3c;
            background-color: #fddede;
            border: 1px solid #e74c3c;
            padding: 10px;
            border-radius: 4px;
        }}
        @media (max-width: 768px) {{
            body {{ margin: 0 auto; }} /* Ajuste para móviles */
            .report-header h1 {{ font-size: 1.8em; }}
            .device-header {{ font-size: 1.2em; flex-direction: column; align-items: flex-start; gap: 5px; }}
            .device-header small {{ font-size: 0.8em; }}
            .summary-card {{
                flex-direction: column;
                gap: 10px;
            }}
            .summary-item {{
                width: 100%; /* Ocupa todo el ancho disponible */
                max-width: none; /* Permitir que ocupe todo el ancho */
                margin-bottom: 10px; /* Añadido margen inferior */
            }}
            .ports-list {{
                grid-template-columns: 1fr; /* Una columna en móviles */
            }}
            .port-block {{ max-width: none; }}
            th, td {{ padding: 8px; font-size: 0.9em; }} /* Tablas generales más pequeñas */
            .port-details th, .port-details td {{ padding: 6px 8px; font-size: 0.85em; }} /* Tablas de puerto más pequeñas */
        }}
    </style>
</head>
<body>
    <div class="report-header">
        <h1>Reporte de Escaneo de Red</h1>
        <p>Generado el: {generation_time}</p>
        <p>Objetivo del escaneo: {target}</p>
    </div>
    
    <div class="summary-card">
        <div class="summary-item">
            <h3>Total Dispositivos</h3>
            <p>{device_count}</p>
        </div>
        <div class="summary-item">
            <h3>Dispositivos Windows</h3>
            <p>{windows_count}</p>
        </div>
        <div class="summary-item">
            <h3>Dispositivos Linux</h3>
            <p>{linux_count}</p>
        </div>
        <div class="summary-item">
            <h3>Dispositivos de Red</h3>
            <p>{network_count}</p>
        </div>
        <div class="summary-item">
            <h3>Dispositivos Desconocidos</h3>
            <p>{unknown_count}</p>
        </div>
    </div>
    
    <div class="devices-container">
        {devices_html}
    </div>
    
    <footer>
        <p>Reporte generado por Network Scanner | {generation_time}</p>
    </footer>
</body>
</html>"""

    def _get_os_name(self, device: Device) -> str:
        """Obtiene un nombre de SO legible del dispositivo."""
        if device.os_info and isinstance(device.os_info, dict):
            # Priorizar 'name' si existe y es informativo
            if 'name' in device.os_info and device.os_info['name'] and device.os_info['name'] != "Unknown":
                return device.os_info['name']
            # Construir a partir de osfamily y osgen si 'name' no es bueno
            if 'osfamily' in device.os_info and device.os_info['osfamily']:
                name_parts = [device.os_info['osfamily']]
                if 'osgen' in device.os_info and device.os_info['osgen']:
                    name_parts.append(device.os_info['osgen'])
                return " ".join(name_parts)
        return "Sistema Operativo Desconocido"


    def _generate_ports_table(self, ports: List[Dict[str, Any]], port_type: str) -> str:
        """Genera bloques HTML para los puertos del dispositivo."""
        if not ports:
            return ""
            
        port_blocks_html = []
        for port_info in ports: # Renombrado 'port' a 'port_info' para evitar colisión con HtmlExporter.port
            try:
                port_number = port_info.get('port', port_info.get('number', 'N/A'))
                state = port_info.get('state', 'unknown')
                service = port_info.get('service', port_info.get('service_name', port_info.get('name', '')))
                product = port_info.get('product', '')
                version = port_info.get('version', '')
                extra = port_info.get('extrainfo', port_info.get('extra', ''))
                
                state_str = str(state).lower()
                if state_str == 'open':
                    state_class = "port-open"
                elif state_str == 'closed':
                    state_class = "port-closed"
                elif state_str == 'filtered':
                    state_class = "port-filtered"
                else: # Default para 'unknown', 'open|filtered', etc.
                    state_class = "port-filtered" # O una clase "port-unknown" si la defines
                
                product_str = f"{product} {version}".strip() if product or version else 'N/A'
                service_str = service or 'N/A'
                extra_str = extra or 'N/A'

                # Escapar caracteres HTML en los datos del usuario para prevenir XSS
                service_str = escape(service_str)
                product_str = escape(product_str)
                extra_str = escape(extra_str)

                port_block = f"""
                <div class="port-block">
                    <div class="port-header">
                        <span class="port-number">Puerto {port_number}</span>
                        <span class="{state_class}">{escape(state_str.upper())}</span>
                    </div>
                    <table class="port-details">
                        <tr><th>Servicio:</th><td>{service_str}</td></tr>
                        <tr><th>Producto:</th><td>{product_str}</td></tr>
                        <tr><th>Extra Info:</th><td>{extra_str}</td></tr>
                    </table>
                </div>""" # No .strip() aquí para mantener formato si se usa join con \n luego
                port_blocks_html.append(port_block)
            except Exception as e:
                print(f"Error generando bloque de puerto: {e}") # Considerar logging en lugar de print
                continue
        
        if not port_blocks_html:
            return ""
            
        return f"""
        <div class="device-section">
            <h3>PUERTOS {port_type.upper()}</h3>
            <div class="ports-list">
                {''.join(port_blocks_html)}
            </div>
        </div>
        """.strip() # .strip() aquí para el device-section completo

    def _format_value_for_html(self, value: Any) -> str:
        """Formatea valores para mostrarlos de forma segura y legible en HTML."""
        if value is None:
            return "N/A"
        
        # Si es una lista de primitivas
        if isinstance(value, list) and all(not isinstance(item, (dict, list)) for item in value):
            return ", ".join(escape(str(v)) for v in value) if value else "N/A"

        # Si es una lista de diccionarios (ej. osclass en Nmap os_info)
        if isinstance(value, list) and value and isinstance(value[0], dict):
            html_parts = []
            for item_dict in value:
                if isinstance(item_dict, dict):
                    sub_parts = [f"<strong>{escape(str(k))}:</strong> {escape(str(v))}" for k,v in item_dict.items()]
                    html_parts.append("<li>" + "; ".join(sub_parts) + "</li>")
            return "<ul>" + "".join(html_parts) + "</ul>" if html_parts else "N/A"

        # Si es un diccionario
        if isinstance(value, dict):
            html_parts = [f"<li><strong>{escape(str(k))}:</strong> {escape(str(v))}</li>" for k,v in value.items()]
            return "<ul>" + "".join(html_parts) + "</ul>" if html_parts else "N/A"
        
        return escape(str(value))


    def _generate_device_info_table(self, device: Device) -> str:
        """Genera tabla HTML para la información básica del dispositivo."""
        rows_html = []
        
        # Información básica
        if hasattr(device, 'ip_address') and device.ip_address:
            rows_html.append(f'<tr><th>IP Address</th><td>{self._format_value_for_html(device.ip_address)}</td></tr>')
        if hasattr(device, 'hostname') and device.hostname and device.hostname != getattr(device, 'ip_address', ''):
            rows_html.append(f'<tr><th>Hostname</th><td>{self._format_value_for_html(device.hostname)}</td></tr>')
        if hasattr(device, 'mac_address') and device.mac_address:
            rows_html.append(f'<tr><th>MAC Address</th><td>{self._format_value_for_html(device.mac_address)}</td></tr>')
        if hasattr(device, 'vendor') and device.vendor:
            rows_html.append(f'<tr><th>Vendor</th><td>{self._format_value_for_html(device.vendor)}</td></tr>')
        
        # Información del Sistema Operativo
        os_name_display = self._get_os_name(device) # Usa el método mejorado
        rows_html.append(f'<tr><th>Operating System</th><td>{self._format_value_for_html(os_name_display)}</td></tr>')
        
        # Detalles adicionales del SO si os_info es un diccionario y tiene más claves
        if hasattr(device, 'os_info') and isinstance(device.os_info, dict):
            # Excluir 'name', 'osfamily', 'osgen' si ya se usaron en _get_os_name o son redundantes
            # Mostrar otras claves útiles de os_info
            keys_to_show = ['type', 'accuracy', 'osclass', 'cpe'] # CPE puede ser una lista
            for key in keys_to_show:
                if key in device.os_info and device.os_info[key]:
                    # Capitalizar y reemplazar '_' para la cabecera de la tabla
                    display_key = key.replace("_", " ").replace("os", "OS ").title()
                    rows_html.append(f'<tr><th>{self._format_value_for_html(display_key)}</th><td>{self._format_value_for_html(device.os_info[key])}</td></tr>')
        
        # Información de Hardware
        if hasattr(device, 'hardware_info') and device.hardware_info and isinstance(device.hardware_info, dict):
            for key, value in device.hardware_info.items():
                rows_html.append(f'<tr><th>{self._format_value_for_html(key.replace("_", " ").title())}</th><td>{self._format_value_for_html(value)}</td></tr>')
        
        if not rows_html:
            return ""
            
        return f"""
        <div class="device-section">
            <h3>Información del Dispositivo</h3>
            <table>
                <tbody>
                    {''.join(rows_html)}
                </tbody>
            </table>
        </div>
        """.strip()

    def _generate_generic_info_table(self, title: str, info_dict: Optional[Dict[str, Any]]) -> str:
        """Genera una tabla HTML genérica para diccionarios de información."""
        if not info_dict:
            return ""
        
        row_list = []
        for key, value in info_dict.items():
            if value: # Solo añadir si hay valor
                row_list.append(
                    f'<tr><th>{self._format_value_for_html(str(key).replace("_", " ").title())}</th>'
                    f'<td>{self._format_value_for_html(value)}</td></tr>'
                )
        
        if not row_list:
            return ""

        tbody_content = ''.join(row_list)
        # Las tablas genéricas no necesitan <thead> con "Property" y "Value" si la clave ya está en <th>
        return f"""
        <div class="device-section">
            <h3>{self._format_value_for_html(title)}</h3>
            <table>
                <tbody>
                    {tbody_content}
                </tbody>
            </table>
        </div>
        """.strip()


    def _generate_vulnerabilities_table(self, vulnerabilities: Optional[List[Dict[str, Any]]]) -> str:
        """Genera tabla HTML para vulnerabilidades."""
        if not vulnerabilities:
            return ""
        
        row_list = []
        for vuln in vulnerabilities:
            if vuln: # Asegurarse que el diccionario de vulnerabilidad no sea None o vacío
                row_list.append(
                    f'<tr>'
                    f'<td>{self._format_value_for_html(vuln.get("name", "N/A"))}</td>'
                    f'<td>{self._format_value_for_html(vuln.get("severity", "N/A"))}</td>'
                    f'<td>{self._format_value_for_html(vuln.get("description", "No description available"))}</td>'
                    f'</tr>'
                )
        
        if not row_list:
            return ""

        tbody_content = ''.join(row_list)
        return f"""
        <div class="device-section">
            <h3>Vulnerabilidades</h3>
            <table>
                <thead>
                    <tr>
                        <th>Nombre</th>
                        <th>Severidad</th>
                        <th>Descripción</th>
                    </tr>
                </thead>
                <tbody>
                    {tbody_content}
                </tbody>
            </table>
        </div>
        """.strip()

    def _generate_device_html(self, device: Device) -> str:
        """Genera el HTML para un solo dispositivo."""
        try:
            device_name = str(getattr(device, 'hostname', getattr(device, 'ip_address', 'Dispositivo Desconocido')))
            device_ip = str(getattr(device, 'ip_address', 'N/A'))
            
            device_sections_html = [] # Lista para acumular las secciones HTML

            # Información del Dispositivo (ahora incluye <div class="device-section">)
            device_info_html = self._generate_device_info_table(device) # Ahora incluye el wrapper
            if device_info_html:
                device_sections_html.append(device_info_html)

            # Información de Red, Específica (WMI, SSH, SNMP), Adicional
            # Estas usan _generate_generic_info_table que YA incluye <div class="device-section">
            for info_type, attr_name, title in [
                ('Network', 'network_info', 'Información de Red'),
                ('WMI', 'wmi_specific_info', 'Información WMI'),
                ('SSH', 'ssh_specific_info', 'Información SSH'),
                ('SNMP', 'snmp_info', 'Información SNMP'), # Corregido de snmp_specific_info a snmp_info
                ('Additional', 'additional_info', 'Información Adicional')
            ]:
                attr_value = getattr(device, attr_name, None)
                if attr_value: # Check for truthiness (not None, not empty dict/list)
                    specific_info_html = self._generate_generic_info_table(title, attr_value)
                    if specific_info_html:
                        device_sections_html.append(specific_info_html)

            # Puertos TCP y UDP (ya incluyen <div class="device-section">)
            if hasattr(device, 'tcp_ports') and device.tcp_ports:
                network_info_html = self._generate_generic_info_table("Información de Red", device.network_info)
                if network_info_html:
                    device_sections_html.append(network_info_html)
                tcp_table_html = self._generate_ports_table(device.tcp_ports, 'TCP')
                if tcp_table_html:
                    device_sections_html.append(tcp_table_html)
            if hasattr(device, 'udp_ports') and device.udp_ports:
                udp_table_html = self._generate_ports_table(device.udp_ports, 'UDP')
                if udp_table_html:
                    device_sections_html.append(udp_table_html)

            # Vulnerabilidades (ya incluye <div class="device-section">)
            if hasattr(device, 'vulnerabilities') and device.vulnerabilities:
                vuln_table_html = self._generate_vulnerabilities_table(device.vulnerabilities)
                if vuln_table_html:
                    device_sections_html.append(vuln_table_html)
            
            device_content_html = '\n'.join(device_sections_html)

            escaped_device_name = escape(device_name)
            escaped_device_ip = escape(device_ip)

            return f"""
            <div class="device-card">
                <h2 class="device-header">{escaped_device_name} <small>({escaped_device_ip})</small></h2>
                <div class="device-content">
                    {device_content_html}
                </div>
            </div>
            """.strip()
            
        except Exception as e:
            error_msg = f"Error generando HTML del dispositivo: {str(e)}"
            print(error_msg) # Considerar logging
            import traceback
            traceback.print_exc() # Para depuración detallada
            return f"""
            <div class="device-card">
                <h2 class="device-header error">Error al Generar Reporte del Dispositivo</h2>
                <div class="device-content">
                    <p class="error">{self._format_value_for_html(error_msg)}</p>
                </div>
            </div>
            """.strip()
            
    def generate_report(self, devices: List[Device], target: str = "Escaneo de Red") -> str:
        """
        Genera un reporte HTML para la lista de dispositivos dada.
        """
        # Asegurarse de que devices sea una lista, incluso si está vacío o es None
        if not devices:
             # Devolver un HTML básico indicando que no hay dispositivos
            return """<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>Reporte Vacío</title></head>
<body>
    <h1>Reporte de Escaneo de Red</h1>
    <p>No se encontraron dispositivos en los resultados del escaneo.</p>
</body>
</html>"""
        
        device_count = len(devices)
        windows_count = 0
        linux_count = 0
        network_device_count = 0 # Renombrado para evitar colisión con variable 'network_count' en la plantilla.
        unknown_os_count = 0     # Renombrado para evitar colisión.
        
        devices_html_list = [] # Lista para el HTML de cada dispositivo
        
        for device in devices:
            try:
                device_html = self._generate_device_html(device)
                if device_html: # Asegurarse que no sea None o vacío
                    devices_html_list.append(device_html)
                
                # Contar tipos de SO
                os_name_lower = self._get_os_name(device).lower()
                if 'windows' in os_name_lower:
                    windows_count += 1
                elif any(distro in os_name_lower for distro in ['linux', 'ubuntu', 'debian', 'centos', 'fedora', 'unix']):
                    linux_count += 1
                elif any(net_dev_type in os_name_lower for net_dev_type in ['router', 'switch', 'firewall', 'ios', 'junos', 'network device']):
                    network_device_count += 1
                elif os_name_lower == "sistema operativo desconocido": # Comparar con el string exacto de _get_os_name
                    unknown_os_count += 1
                else: # Otros OS que no caen en las categorías anteriores
                    unknown_os_count += 1 # O una categoría 'Otros' si se prefiere
                    
            except Exception as e:
                print(f"Error generando HTML para dispositivo {getattr(device, 'ip_address', 'desconocido')}: {e}")
        
        # Si no se pudo generar HTML para ningún dispositivo, devolver un reporte de error
        if not devices_html_list:
             return """<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>Error al Generar Reporte</title></head>
<body>
    <h1>Error al Generar Reporte</h1>
    <p class="error">No se pudo generar contenido HTML para ningún dispositivo escaneado.</p>
    <p>Por favor, revise los logs para más detalles.</p>
</body>
</html>"""
        
        # Asegurar que unknown_os_count no sea negativo si la lógica de arriba es exhaustiva
        # unknown_os_count = device_count - (windows_count + linux_count + network_device_count)
        # La lógica anterior de ir sumando a unknown_os_count es más robusta si hay OS no categorizados.

        # Formatear el reporte principal
        try:
            # Usar los nombres de variable correctos para la plantilla
            report = self.html_template.format(
                generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                target=self._format_value_for_html(target), # Escapar el target
                device_count=device_count,
                windows_count=windows_count,
                linux_count=linux_count,
                network_count=network_device_count, # Mapear a 'network_count' de la plantilla
                unknown_count=unknown_os_count,     # Mapear a 'unknown_count' de la plantilla
                devices_html='\n'.join(devices_html_list)
            )
            return report
            
        except KeyError as ke:
            error_msg = f"Error de plantilla: Falta la clave {str(ke)} en los datos de formato."
            print(error_msg)
            # Devolver un HTML de error para que html_content no sea None
            return f"""<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>Error de Plantilla</title></head>
<body>
    <h1>Error de Plantilla</h1>
    <p class="error">Se encontró un error al generar el reporte debido a una clave faltante en la plantilla: {self._format_value_for_html(str(ke))}</p>
    <p>Por favor, revise la plantilla HTML y asegúrese de que todas las llaves de estilo CSS ({{}}) estén correctamente escapadas como {{{{}}}} y {{{{'}}'}}}} si están dentro de la cadena de formato principal.</p>
</body>
</html>"""
        except Exception as e:
            error_msg = str(e)
            print(f"Error generando reporte: {error_msg}")
            return f"""
            <!DOCTYPE html><html><head><meta charset="UTF-8"><title>Error</title></head>
            <body><h1>Error al Generar Reporte</h1><p class="error">{self._format_value_for_html(error_msg)}</p></body></html>
            """ # HTML de error simplificado
    
    def save_report(self, devices: List[Device], output_path: str, target: str = "Escaneo de Red") -> bool:
        """
        Genera un reporte HTML y lo guarda en la ruta especificada.
        """
        try:
            html_content = self.generate_report(devices, target)
            
            # generate_report ahora siempre devuelve una cadena, incluso en caso de error.
            # No necesitamos verificar si es None aquí.
            
            output_dir = os.path.dirname(os.path.abspath(output_path))
            if output_dir and not os.path.exists(output_dir): # Crear directorio solo si no existe
                try:
                    os.makedirs(output_dir, exist_ok=True)
                except Exception as dir_error:
                    print(f"Error creando directorio de salida {output_dir}: {dir_error}")
                    return False # No continuar si no se puede crear el directorio
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"Reporte HTML guardado exitosamente en {output_path}")
            return True
                
        except Exception as e: # Captura cualquier otra excepción no manejada arriba
            import traceback
            print(f"Error inesperado en save_report: {e}")
            print(traceback.format_exc())
            return False
