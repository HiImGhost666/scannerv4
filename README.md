# MiProyectoRed: Herramienta Avanzada de Inventariado y Monitoreo de Red

<div align="center">
  <img src="miproyectored/gui/resources/SG - Logo Laberit principal.png" alt="MiProyectoRed Banner">
</div>

## 🌐 Visión General

MiProyectoRed es una solución integral para la gestión, monitorización y auditoría de seguridad de redes corporativas. Esta herramienta combina capacidades avanzadas de escaneo de red con análisis de seguridad, visualización de topología y gestión de inventario, todo integrado en una interfaz gráfica intuitiva y moderna.

### Diseñada para profesionales de TI que necesitan:

- **Inventariar** todos los dispositivos conectados a su red corporativa
- **Monitorizar** cambios y eventos en tiempo real
- **Analizar** posibles vulnerabilidades y riesgos de seguridad
- **Documentar** la infraestructura de red con informes detallados
- **Visualizar** la topología de red de forma interactiva

## 📋 Características Principales

### 🔍 Detección y Escaneo de Red

- **Escaneo completo**: Detección de dispositivos en rangos de IP configurables, con optimización para redes de todos los tamaños
- **Escaneo inteligente**: Algoritmos adaptativos que ajustan la velocidad y profundidad del escaneo según las características de la red
- **Detección automática de red**: Identificación automática de la red local y sugerencia de rangos óptimos para escanear
- **Programación de escaneos**: Configuración de escaneos periódicos automáticos con frecuencia personalizable
- **Modos de escaneo**: 
  - Modo rápido: Enfocado en la detección básica de hosts
  - Modo estándar: Equilibrio entre velocidad y detalle
  - Modo profundo: Análisis exhaustivo incluyendo fingerprinting de OS y detección de servicios
  - Modo personalizado: Configuración avanzada de parámetros

### 🖥️ Identificación de Dispositivos y Servicios

- **Recopilación exhaustiva de datos**:
  - Dirección IP y hostname
  - Dirección MAC y fabricante del dispositivo
  - Sistema operativo (con nivel de confianza)
  - Tiempo de actividad estimado
  - Hardware (cuando sea posible obtenerlo)
  - Servicios y puertos activos
  
- **Detección de servicios**: Identificación de más de 50 servicios comunes, incluyendo:
  - Servicios web (HTTP, HTTPS, con detección de CMS y versiones)
  - Servicios de administración remota (SSH, Telnet, RDP, VNC)
  - Servicios de archivos (SMB, FTP, SFTP, NFS)
  - Bases de datos (MySQL, PostgreSQL, MSSQL, MongoDB, etc.)
  - Servicios de correo (SMTP, POP3, IMAP)
  - Servicios de infraestructura (DNS, DHCP, LDAP, Kerberos)
  - Servicios de monitorización (SNMP, WMI, IPMI)
  - Servicios multimedia (RTSP, RTP)
  - Protocolos industriales (Modbus, Bacnet, Siemens S7)

- **Clasificación automática**: Categorización de dispositivos como:
  - Enrutadores y firewalls
  - Switches y puntos de acceso
  - Servidores (web, archivos, aplicaciones, bases de datos)
  - Estaciones de trabajo
  - Dispositivos IoT
  - Impresoras y dispositivos multifunción
  - Equipos de videovigilancia
  - Dispositivos industriales

### 🔔 Monitoreo en Tiempo Real

- **Sistema avanzado de vigilancia de red**:
  - Detección de nuevos dispositivos que se conectan a la red
  - Identificación de cambios en configuraciones o servicios
  - Alerta sobre caídas de dispositivos críticos
  - Monitoreo de patrones de tráfico anómalos

- **Motor de reglas personalizable**:
  - Creación de reglas basadas en condiciones específicas
  - Umbrales configurables para diferentes métricas
  - Soporte para operadores lógicos complejos
  - Posibilidad de activar/desactivar reglas según necesidades

- **Sistema de notificaciones multi-canal**:
  - Alertas en tiempo real en la interfaz de usuario
  - Registro detallado en logs del sistema
  - Notificaciones por correo electrónico (configurable)
  - Exportación de registros de eventos para análisis posterior
  
- **Panel de control de eventos**:
  - Vista centralizada de todos los eventos detectados
  - Filtrado por tipo, gravedad, fecha y dispositivo
  - Capacidad de marcar eventos como resueltos o ignorados
  - Estadísticas históricas de eventos

### 🌐 Visualización y Topología

- **Mapa de red interactivo**:
  - Representación visual de todos los dispositivos y sus conexiones
  - Visualización basada en D3.js para una experiencia fluida
  - Disposición automática optimizada con múltiples algoritmos
  - Zoom, arrastre y reorganización manual de nodos

- **Características del mapa**:
  - Iconos distintivos según tipo de dispositivo
  - Código de colores para estado y nivel de riesgo
  - Indicadores visuales de latencia y calidad de conexión
  - Agrupación automática por subredes o etiquetas

- **Interacción avanzada**:
  - Menú contextual con acciones específicas para cada dispositivo
  - Vista de detalles al pasar el cursor sobre elementos
  - Animación de rutas de tráfico entre dispositivos seleccionados
  - Modo de presentación para documentación y reportes

- **Exportación y compartición**:
  - Guardado del mapa como imagen PNG/SVG
  - Exportación a HTML interactivo con todas las funcionalidades
  - Impresión optimizada de topología
  - Generación de QR para acceso rápido al mapa desde dispositivos móviles

### 📊 Gestión de Inventario

- **Base de datos centralizada**:
  - Almacenamiento eficiente en SQLite con soporte para migración a MySQL/PostgreSQL
  - Modelo de datos optimizado para consultas rápidas
  - Indexación avanzada para inventarios extensos
  - Compresión y archivado automático de datos históricos

- **Seguimiento histórico**:
  - Registro completo de todos los cambios en la red
  - Comparación visual entre diferentes puntos temporales
  - Análisis de tendencias de crecimiento y cambios
  - Línea de tiempo interactiva de la evolución de la red

- **Organización y clasificación**:
  - Sistema de etiquetado flexible con categorías personalizables
  - Agrupación jerárquica por ubicación, departamento o función
  - Asignación de propietarios y responsables a dispositivos
  - Campos personalizados para adaptarse a necesidades específicas

- **Búsqueda y filtrado avanzado**:
  - Motor de búsqueda con soporte para consultas complejas
  - Filtros combinados por múltiples criterios
  - Guardado y recuperación de búsquedas frecuentes
  - Actualización en tiempo real de resultados filtrados

### 📝 Exportación e Informes

- **Generación flexible de informes**:
  - Informes ejecutivos con resumen general
  - Informes técnicos detallados para administradores
  - Informes de seguridad orientados a cumplimiento normativo
  - Informes personalizados con selección de campos específicos

- **Múltiples formatos de exportación**:
  - CSV y Excel para análisis en hojas de cálculo
  - JSON para integración con otras herramientas
  - PDF para documentación formal
  - HTML para visualización interactiva

- **Personalización avanzada**:
  - Plantillas configurables con marca corporativa
  - Selección de secciones y nivel de detalle
  - Inclusión opcional de gráficos y visualizaciones
  - Programación de generación automática periódica

- **Estadísticas y métricas**:
  - Distribución de dispositivos por tipo, fabricante y sistema operativo
  - Análisis de tendencias de crecimiento de la red
  - Evolución del nivel de seguridad a lo largo del tiempo
  - Métricas de rendimiento y disponibilidad

### 🎨 Interfaz y Usabilidad

- **Diseño moderno y profesional**:
  - Interfaz basada en ttkbootstrap con tema personalizado
  - Paleta de colores corporativos:
    - Azul oscuro (#091F2C) - Color principal
    - Rojo (#C10016) - Acentos y alertas
    - Púrpura suave (#B4B5DF) - Elementos secundarios
    - Azul medio (#7A99AC) - Navegación
    - Azul claro (#A6BBC8) - Fondos alternativos
  - Diseño responsivo adaptable a diferentes resoluciones
  - Modo oscuro/claro conmutable

- **Experiencia de usuario optimizada**:
  - Operaciones asíncronas para mantener la interfaz receptiva
  - Indicadores de progreso para tareas prolongadas
  - Atajos de teclado para acciones frecuentes
  - Tutoriales integrados para nuevos usuarios

- **Conexión directa a dispositivos**:
  - Apertura de interfaces web en navegador integrado
  - Cliente SSH incorporado para conexión directa
  - Iniciador de sesiones RDP para equipos Windows
  - Acceso a paneles de administración de dispositivos

- **Gestión segura de credenciales**:
  - Almacenamiento cifrado de contraseñas con Fernet
  - Soporte para autenticación por clave SSH
  - Integración con gestores de contraseñas corporativos
  - Políticas de caducidad y rotación de credenciales

## 🔧 Requisitos Técnicos

### Requisitos del Sistema

- **Sistema Operativo**:
  - Windows 10/11 (64 bits)
  - Ubuntu 20.04 LTS o superior
  - Debian 11 o superior
  - CentOS 8 o superior
  - macOS 11 (Big Sur) o superior

- **Hardware Recomendado**:
  - Procesador: Quad-core 2.5 GHz o superior
  - Memoria RAM: 8 GB mínimo (16 GB recomendado para redes grandes)
  - Almacenamiento: 500 MB para la aplicación + espacio para base de datos (variable según tamaño de red)
  - Tarjeta de red: Gigabit Ethernet recomendada

- **Dependencias del Sistema**:
  - Python 3.6 o superior
  - Nmap 7.80 o superior
  - SQLite 3.30 o superior
  - wkhtmltopdf (para exportación a PDF)

### Bibliotecas Python

```
# GUI
ttkbootstrap>=1.0.0
tkinter

# Escaneo de red
python-nmap>=0.7.1

# Acceso SSH
paramiko>=2.9.0

# Acceso SNMP
pysnmp>=4.4.12

# Acceso WMI (solo para Windows)
wmi>=1.5.1
pywin32>=303; sys_platform == 'win32'

# Base de datos
sqlite3

# Exportación
pandas>=1.3.0
openpyxl>=3.0.9
jinja2>=3.0.0
pdfkit>=1.0.0
weasyprint>=54.0

# Utilidades
typing
logging
```

## 🚀 Instalación

### Instalación Básica

1. **Instalar Python**:
   - Descarga e instala Python 3.6 o superior desde [python.org](https://python.org)
   - Asegúrate de marcar la opción "Añadir Python al PATH" durante la instalación en Windows

2. **Instalar Nmap**:
   - Windows: Descarga e instala desde [nmap.org](https://nmap.org/download.html)
   - Linux (Debian/Ubuntu): `sudo apt-get install nmap`
   - Linux (CentOS/RHEL): `sudo yum install nmap`
   - macOS (con Homebrew): `brew install nmap`

3. **Clonar o descargar el repositorio**:
   ```bash
   git clone https://github.com/tu-usuario/miproyectored.git
   cd miproyectored
   ```

4. **Instalar dependencias Python**:
   ```bash
   pip install -r requirements.txt
   ```

5. **Ejecutar la aplicación**:
   ```bash
   python main.py
   ```

### Instalación Avanzada

#### Instalación con Entorno Virtual

```bash
# Crear entorno virtual
python -m venv venv

# Activar entorno virtual
# En Windows:
venv\Scripts\activate
# En Linux/macOS:
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

#### Instalación con Docker

```bash
# Construir la imagen
docker build -t miproyectored .

# Ejecutar el contenedor
docker run -d --name scanner-red -p 8080:8080 --network host miproyectored
```

## 🎮 Guía de Uso

### Primeros Pasos

1. **Iniciar la aplicación**:
   ```bash
   python main.py
   ```

2. **Configuración inicial**:
   - En el primer inicio, se te guiará a través del asistente de configuración
   - Establece las preferencias generales y opciones de escaneo
   - Configura las credenciales predeterminadas (opcional)

3. **Realizar primer escaneo**:
   - Selecciona la pestaña "Escaneo de Red"
   - Ingresa el rango de red o utiliza la detección automática
   - Selecciona el modo de escaneo (rápido, estándar, profundo)
   - Haz clic en "Iniciar Escaneo"

### Flujos de Trabajo Comunes

#### Inventariado de Red

1. Realiza un escaneo completo de la red
2. Revisa la lista de dispositivos detectados
3. Completa manualmente información adicional si es necesario
4. Aplica etiquetas y categorías para organizar
5. Exporta el inventario completo a Excel o PDF

#### Auditoría de Seguridad

1. Configura credenciales de acceso (SSH, SNMP, WMI)
2. Realiza un escaneo en modo profundo con análisis de riesgos activado
3. Revisa las alertas de seguridad clasificadas por nivel de riesgo
4. Examina las recomendaciones para cada vulnerabilidad
5. Genera un informe de seguridad detallado

#### Monitoreo Continuo

1. Configura las reglas de alerta según tus necesidades
2. Activa el monitoreo en tiempo real después de un escaneo completo
3. Establece la frecuencia de verificación de cambios
4. Configura notificaciones para eventos importantes
5. Revisa periódicamente el panel de eventos

#### Documentación de Red

1. Realiza un escaneo completo para obtener información detallada
2. Accede a la vista de topología para visualizar la red
3. Personaliza la vista según necesidades (subredes, tipos, etc.)
4. Exporta el mapa como HTML interactivo o imagen
5. Genera un informe técnico completo con todos los detalles

## 🔍 Funcionalidades Detalladas

### Sistema de Escaneo

El motor de escaneo utiliza una combinación de técnicas para maximizar la precisión y minimizar el impacto en la red:

- **Escaneo de Descubrimiento**: Utiliza una combinación de ping ICMP, TCP SYN, UDP y ARP para detectar hosts activos.
- **Escaneo de Puertos**: Implementa estrategias adaptativas para escanear puertos comunes y detectar servicios.
- **Fingerprinting de OS**: Utiliza técnicas de análisis de paquetes para identificar sistemas operativos.
- **Detección de Servicios**: Combina sondeo de banners, análisis de respuestas y heurísticas para identificar servicios.
- **Análisis de Versiones**: Detecta versiones específicas de servicios para evaluación de seguridad.

### Análisis de Riesgos

El sistema de análisis de riesgos evalúa múltiples factores:

- **Puertos Abiertos**: Asigna puntajes de riesgo según servicios expuestos.
- **Versiones Vulnerables**: Compara con base de datos de vulnerabilidades conocidas.
- **Configuraciones Débiles**: Detecta configuraciones inseguras comunes.
- **Protocolos Obsoletos**: Identifica protocolos considerados inseguros.
- **Autenticación Débil**: Evalúa la fortaleza de los mecanismos de autenticación.

### Sistema de Monitoreo

El monitoreo en tiempo real utiliza diversas técnicas:

- **Escaneo Periódico Ligero**: Verifica cambios sin sobrecargar la red.
- **Análisis de ARP**: Detecta nuevos dispositivos que se unen a la red.
- **Verificación de Servicios**: Comprueba periódicamente la disponibilidad de servicios críticos.
- **Detección de Cambios**: Identifica modificaciones en configuraciones y servicios.
- **Alertas Inteligentes**: Reduce falsos positivos mediante análisis contextual.

## 🔌 Integración con Otras Herramientas

MiProyectoRed está diseñado para integrarse con otras herramientas de gestión y seguridad:

- **Exportación para SIEM**: Formatos compatibles con sistemas SIEM populares.
- **API REST**: Interfaz programática para integración con otras aplicaciones (próximamente).
- **Integración con Sistemas de Tickets**: Capacidad para crear tickets en sistemas de soporte.
- **Autenticación LDAP/AD**: Soporte para autenticación centralizada (próximamente).
- **Importación/Exportación CMDB**: Compatibilidad con bases de datos de gestión de configuración.

## 📚 Estructura del Proyecto

```
miproyectored/
├── auth/                 # Gestión de autenticación y credenciales
├── controller/           # Controladores de la aplicación
├── export/               # Módulos de exportación e informes
├── gui/                  # Interfaz gráfica de usuario
├── inventory/            # Gestión de inventario y base de datos
├── model/                # Modelos de datos
├── risk/                 # Análisis de riesgos y seguridad
├── scanner/              # Motor de escaneo y descubrimiento
├── util/                 # Utilidades comunes
├── main.py               # Punto de entrada principal
└── network_inventory.db  # Base de datos SQLite
```

## 📜 Notas de Seguridad

- **Uso Responsable**: Esta herramienta debe utilizarse únicamente en redes sobre las que se tenga autorización explícita.
- **Impacto del Escaneo**: El escaneo intensivo puede generar carga en la red y ser detectado por sistemas de seguridad.
- **Almacenamiento de Credenciales**: Las credenciales se almacenan cifradas, pero se recomienda limitar su uso a lo estrictamente necesario.
- **Límites de Detección**: Ninguna herramienta de escaneo es infalible; algunos dispositivos pueden no ser detectados o identificados correctamente.
- **Falsos Positivos**: El análisis de riesgos puede generar falsos positivos que deben ser verificados manualmente.

## 🤝 Contribución

¡Las contribuciones son bienvenidas! Si deseas mejorar MiProyectoRed:

1. Haz un fork del repositorio
2. Crea una rama para tu característica (`git checkout -b feature/amazing-feature`)
3. Realiza tus cambios y haz commit (`git commit -m 'Add some amazing feature'`)
4. Sube tus cambios (`git push origin feature/amazing-feature`)
5. Abre un Pull Request

### Áreas de Mejora Prioritarias

- Optimización del rendimiento en redes muy grandes
- Soporte para más protocolos y servicios
- Mejoras en la detección de sistemas operativos
- Interfaz web alternativa (en desarrollo)
- Soporte para escaneo remoto y distribuido

## 📄 Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo LICENSE para más detalles.

---

<div align="center">
  <p>Desarrollado por los alumnos en prácticas</p>
  <p style="color: #091F2C;">© 2025 MiProyectoRed - Todos los derechos reservados</p>
</div>
