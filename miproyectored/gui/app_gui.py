#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de interfaz gráfica para la herramienta de escaneo de red (adaptado para miproyectored)

Este módulo implementa la interfaz gráfica de usuario utilizando ttkbootstrap
para mostrar y controlar el escaneo de red.
"""

import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
import threading
import time
import os
import sys

# Ensure the project root is in sys.path for relative imports when running the script directly.
# This allows Python to find the 'miproyectored' module.
_project_root_app_gui = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if _project_root_app_gui not in sys.path:
    sys.path.insert(0, _project_root_app_gui)
import logging
import socket
import sqlite3
import webbrowser
import tempfile
import subprocess
import atexit
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from PIL import Image, ImageTk  # Añadido para manejar imágenes

# Importar módulos del proyecto miproyectored
from miproyectored.scanner.nmap_scanner import NmapScanner
from miproyectored.scanner.wmi_scanner import WmiScanner
from miproyectored.scanner.ssh_scanner import SshScanner
from miproyectored.scanner.snmp_scanner import SnmpScanner
from miproyectored.model.device import Device
from miproyectored.risk.risk_analyzer import RiskAnalyzer
from miproyectored.inventory.inventory_manager import InventoryManager
from miproyectored.export import html_exporter
from miproyectored.auth.network_credentials import NetworkCredentials
from miproyectored.util.network_utils import detect_local_networks # Importar la utilidad de detección de red
from miproyectored.model.network_report import NetworkReport # Añadido para _export_data
# Importar nuevos módulos para escaneo detallado

# Configuración del sistema de logging
logger = logging.getLogger('miproyectored')
logger.setLevel(logging.DEBUG)

# Evitar la propagación al logger raíz para evitar duplicados
logger.propagate = False

# Configurar manejadores solo si no existen ya
if not logger.handlers:
    # Configurar manejador de archivo (modo 'w' para sobrescribir en cada ejecución)
    log_file_path = os.path.join(os.path.dirname(__file__), 'network_scanner_gui.log')
    
    # Eliminar el archivo de log existente si existe
    try:
        if os.path.exists(log_file_path):
            os.remove(log_file_path)
    except Exception as e:
        print(f"No se pudo eliminar el archivo de log existente: {e}")
    
    # Crear un nuevo manejador de archivo en modo escritura
    file_handler = logging.FileHandler(log_file_path, mode='w', encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    
    # Configurar manejador de consola
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)
    
    # Formato de los mensajes
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Añadir manejadores al logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # Configurar el logger raíz para que no muestre mensajes no deseados
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.WARNING)
    for hdlr in root_logger.handlers[:]:
        root_logger.removeHandler(hdlr)
    
    # Escribir encabezado del log
    logger.info("=" * 80)
    logger.info(f"Iniciando nueva sesión - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("=" * 80)

class NetworkScannerGUI(ttk.Window):
    """
    Clase principal para la interfaz gráfica de la herramienta de escaneo de red.
    """
    def __init__(self):
        """Inicializa la interfaz gráfica."""
        try:
            # Variable para almacenar el proceso del servidor SQLite Web
            self.sqlite_web_process = None
            
            # Inicializar la ventana principal
            super().__init__(themename="litera")
            
            # Configurar el manejador de cierre después de inicializar la ventana
            self.protocol("WM_DELETE_WINDOW", self.on_close)
            
            # Definición de colores corporativos
            self.COLORES = {
                'azul_oscuro': "#091F2C",    # Pantone 5395 C (color primario)
                'rojo': "#C10016",           # Pantone 3517 C (color primario)
                'purpura_suave': "#B4B5DF",  # Pantone 270 C (complementario)
                'azul_medio': "#7A99AC",     # Pantone 5425 C (complementario)
                'azul_claro': "#A6BBC8",     # Pantone 5435 C (complementario)
                'blanco': "#FFFFFF"
            }
            
            # Personalizar el tema con colores corporativos
            self._apply_corporate_colors()
            
            self.title("Herramienta de Escaneo de Red - MiProyectoRed")
            self.geometry("1300x750") # Aumentado el tamaño para más detalles
            self.minsize(1000, 600)

            self.nmap_scanner = NmapScanner() # Usar NmapScanner del proyecto
            self.risk_analyzer = RiskAnalyzer() # Usar RiskAnalyzer del proyecto

            # Inicializar escáneres específicos
            self.wmi_scanner = WmiScanner()
            self.ssh_scanner = SshScanner()
            self.snmp_scanner = SnmpScanner()

            # Inicializar base de datos
            self.inventory_manager = InventoryManager()

            # Variables para almacenar los resultados del escaneo
            self.scan_results: List[Device] = []
            self.filtered_results: List[Device] = []
            self.selected_device_ip: Optional[str] = None

            # Variable para el arrastre de columnas
            self._drag_data = {"x": 0, "y": 0, "item": None}

            # Contadores para tipos de dispositivos
            self.windows_devices_count = 0
            self.linux_devices_count = 0
            self.snmp_devices_count = 0

            # Variables para las credenciales
            self.ssh_username = ttk.StringVar()
            self.ssh_password = ttk.StringVar()
            self.ssh_key_file = ttk.StringVar()
            self.snmp_community = ttk.StringVar(value="public") # Valor por defecto para SNMP
            self.wmi_username = ttk.StringVar()
            self.wmi_password = ttk.StringVar()
            self.wmi_domain = ttk.StringVar() # Añadido para WMI

            # Variable para habilitar/deshabilitar escaneo WMI
            self.wmi_scan_enabled = ttk.BooleanVar(value=False)

            # Variable para habilitar/deshabilitar escaneo automático
            # self.auto_scan_enabled = ttk.BooleanVar(value=True) # Eliminada, reemplazada por toggles individuales

            # Variables para habilitar/deshabilitar escaneos detallados individuales
            self.snmp_detailed_scan_enabled = ttk.BooleanVar(value=False) # Para SNMP
            self.ssh_detailed_scan_enabled = ttk.BooleanVar(value=False)  # Para SSH

            # --- Lógica actualizada para el Combobox de Rango de Red ---
            # ASUNCIÓN IMPORTANTE: Se asume que detect_local_networks() ahora devuelve
            # una List[Tuple[str, str]], por ejemplo: [("192.168.1.0/24", "Ethernet 0"), ...]
            # Si detect_local_networks() no ha sido modificada para proveer nombres de interfaz,
            # esta funcionalidad no mostrará los nombres.
            try:
                detected_networks_with_names: List[Tuple[str, str]] = detect_local_networks()
                if not detected_networks_with_names:
                    logger.warning("detect_local_networks() no devolvió ninguna red. Usando default.")
                    detected_networks_with_names = [("192.168.1.0/24", "Default")]
            except Exception as e:
                logger.error(f"Error al llamar a detect_local_networks(): {e}. Usando default.", exc_info=True)
                detected_networks_with_names = [("192.168.1.0/24", "ErrorDefault")]

            self.available_network_details: List[Tuple[str, str]] = [] # Almacena (ip_real, texto_mostrado)
            self.combobox_display_values_list: List[str] = []

            for ip_r, if_name in detected_networks_with_names:
                display_text = f"{ip_r} ({if_name})"
                self.available_network_details.append((ip_r, display_text))
                self.combobox_display_values_list.append(display_text)

            if not self.available_network_details: # Fallback si todo lo anterior falla
                default_ip = "192.168.1.0/24"
                default_display = f"{default_ip} (Fallback)"
                self.available_network_details.append((default_ip, default_display))
                self.combobox_display_values_list.append(default_display)

            initial_actual_ip = self.available_network_details[0][0]
            initial_display_value_for_combobox = self.available_network_details[0][1]

            self.network_range = ttk.StringVar(value=initial_actual_ip) # Almacena el IP real para escanear
            self.combobox_selected_text_var = ttk.StringVar(value=initial_display_value_for_combobox) # Para el texto del Combobox
            # --- Fin de la lógica actualizada ---

            self.search_filter = ttk.StringVar()
            self.search_filter.trace_add("write", self._apply_filter)

            self.scan_status = ttk.StringVar(value="Listo para escanear.")

            self._create_widgets()

            self.protocol("WM_DELETE_WINDOW", self._on_closing)

            logger.info("Interfaz gráfica inicializada correctamente")
        except Exception as e:
            logger.error(f"Error al inicializar la interfaz gráfica: {e}", exc_info=True)
            messagebox.showerror("Error de Inicialización", f"Error al inicializar la aplicación: {e}")
            self.destroy()

    def _apply_corporate_colors(self):
        """Aplica los colores corporativos al tema actual"""
        style = ttk.Style()

        # Configurar colores base
        style.configure("TButton",
                        background=self.COLORES['azul_oscuro'],
                        foreground=self.COLORES['blanco'])

        style.configure("TLabel",
                        foreground=self.COLORES['azul_oscuro'])

        style.configure("TFrame",
                        background=self.COLORES['blanco'])

        style.configure("TLabelframe",
                        background=self.COLORES['blanco'],
                        foreground=self.COLORES['azul_oscuro'])

        style.configure("TLabelframe.Label",
                        foreground=self.COLORES['azul_oscuro'],
                        font=('TkDefaultFont', 10, 'bold'))

        # Configurar Treeview
        style.configure("Treeview",
                        background=self.COLORES['blanco'],
                        foreground=self.COLORES['azul_oscuro'],
                        fieldbackground=self.COLORES['blanco'])

        style.configure("Treeview.Heading",
                        background=self.COLORES['azul_oscuro'],
                        foreground=self.COLORES['blanco'],
                        font=('TkDefaultFont', 10, 'bold'))

        style.map("Treeview",
                  background=[('selected', self.COLORES['azul_medio'])],
                  foreground=[('selected', self.COLORES['blanco'])])

        # Configurar Notebook
        style.configure("TNotebook",
                        background=self.COLORES['blanco'])

        style.configure("TNotebook.Tab",
                        background=self.COLORES['azul_claro'],
                        foreground=self.COLORES['azul_oscuro'],
                        padding=[10, 2])

        style.map("TNotebook.Tab",
                  background=[('selected', self.COLORES['azul_medio'])],
                  foreground=[('selected', self.COLORES['blanco'])])

        # Configurar Entry
        style.configure("TEntry",
                        foreground=self.COLORES['azul_oscuro'])

        # Estilos específicos
        style.configure("Section.TLabel",
                        font=('TkDefaultFont', 11, 'bold'),
                        foreground=self.COLORES['azul_oscuro'])

        # Botones especiales
        style.configure("Primary.TButton",
                        background=self.COLORES['azul_oscuro'],
                        foreground=self.COLORES['blanco'])

        style.configure("Action.TButton",
                        background=self.COLORES['rojo'],
                        foreground=self.COLORES['blanco'])

        # Botones de estado
        style.configure("success.TButton",
                        background=self.COLORES['rojo'],
                        foreground=self.COLORES['blanco'])

        style.configure("info.TButton",
                        background=self.COLORES['azul_medio'],
                        foreground=self.COLORES['blanco'])

        # Checkbutton
        style.configure("round-toggle.Toolbutton",
                        background=self.COLORES['azul_claro'],
                        foreground=self.COLORES['azul_oscuro'])

        style.map("round-toggle.Toolbutton",
                  background=[('selected', self.COLORES['azul_medio'])],
                  foreground=[('selected', self.COLORES['blanco'])])

    def _create_widgets(self):
        """Crea los widgets de la interfaz gráfica."""
        # Crear la barra de menú principal
        self._create_menu_bar()

        main_pane = ttk.PanedWindow(self, orient=HORIZONTAL)
        main_pane.pack(fill=BOTH, expand=True, padx=10, pady=10)

        # Panel Izquierdo: Controles y Configuración
        left_frame_container = ttk.Frame(main_pane, padding=10)
        left_frame_container.configure(borderwidth=1, relief="solid")
        main_pane.add(left_frame_container, weight=1)

        # Añadir logo encima de la sección de escaneo - TAMAÑO FIJO
        logo_frame = ttk.Frame(left_frame_container)
        logo_frame.pack(fill=X, pady=(0, 5))

        # Ruta al archivo de logo PNG
        logo_path = os.path.join(os.path.dirname(__file__), 'resources', 'logo.png')

        # Cargar y mostrar el logo con tamaño fijo
        if os.path.exists(logo_path):
            try:
                # Cargar la imagen original
                original_img = Image.open(logo_path)

                # AQUÃ PUEDES CAMBIAR EL TAMAÑO FIJO DE LA IMAGEN
                # Modifica estos valores para ajustar el tamaño
                fixed_width = 225  # Ancho fijo en píxeles
                fixed_height = 45  # Altura fija en píxeles

                # Redimensionar la imagen a un tamaño fijo
                resized_img = original_img.resize((fixed_width, fixed_height), Image.LANCZOS)

                # Convertir a formato que tkinter puede mostrar
                self.logo_photo = ImageTk.PhotoImage(resized_img)

                # Crear y centrar el label con la imagen
                self.logo_label = ttk.Label(logo_frame, image=self.logo_photo)
                self.logo_label.pack(pady=5)
            except Exception as e:
                logger.error(f"Error al cargar el logo: {e}")

        # Sección de Escaneo
        scan_frame = ttk.Labelframe(left_frame_container, text="Configuración de Escaneo", padding=10)
        scan_frame.pack(fill=X, pady=5)

        ttk.Label(scan_frame, text="Rango de Red", style="Section.TLabel").pack(fill=X, pady=(0,2))
        # Combobox actualizado para mostrar IP (Nombre Interfaz)
        self.network_range_combobox = ttk.Combobox(
            scan_frame,
            textvariable=self.combobox_selected_text_var, # Vinculado a la variable de texto mostrado
            values=self.combobox_display_values_list,     # Lista de textos formateados
            state="readonly" # Evitar edición manual, solo selección
        )
        self.network_range_combobox.pack(fill=X, pady=(0,5))
        self.network_range_combobox.bind("<<ComboboxSelected>>", self._on_network_range_select)

        # Opción para escaneo SNMP detallado
        snmp_detailed_scan_check = ttk.Checkbutton(
            scan_frame,
            text="Incluir escaneo detallado SNMP",
            variable=self.snmp_detailed_scan_enabled,
            bootstyle="round-toggle"
        )
        snmp_detailed_scan_check.pack(fill=X, pady=2)

        # Opción para escaneo WMI
        wmi_scan_check = ttk.Checkbutton(
            scan_frame,
            text="Incluir escaneo WMI (Windows)",
            variable=self.wmi_scan_enabled,
            bootstyle="round-toggle"
        )
        wmi_scan_check.pack(fill=X, pady=2)

        # Opción para escaneo SSH detallado
        ssh_detailed_scan_check = ttk.Checkbutton(
            scan_frame,
            text="Incluir escaneo detallado SSH",
            variable=self.ssh_detailed_scan_enabled,
            bootstyle="round-toggle"
        )
        ssh_detailed_scan_check.pack(fill=X, pady=2)

        self.scan_button = ttk.Button(scan_frame, text="Iniciar Escaneo", command=self._start_nmap_scan, style="Action.TButton")
        self.scan_button.pack(fill=X, pady=5)

        self.scan_progress = ttk.Progressbar(scan_frame, mode='indeterminate')
        self.scan_progress.pack(fill=X, pady=5)

        ttk.Label(scan_frame, textvariable=self.scan_status).pack(fill=X, pady=2)

        # Sección de Credenciales para escaneo detallado
        creds_frame = ttk.Labelframe(left_frame_container, text="Credenciales para Escaneo Detallado", padding=10)
        creds_frame.pack(fill=X, pady=10)

        # SSH
        ssh_label = ttk.Label(creds_frame, text="SSH (Linux/Unix):", style="Section.TLabel")
        ssh_label.pack(anchor=W)
        ssh_form = ttk.Frame(creds_frame)
        ssh_form.pack(fill=X, padx=10)
        ttk.Label(ssh_form, text="Usuario:").grid(row=0, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(ssh_form, textvariable=self.ssh_username, width=15).grid(row=0, column=1, sticky=EW, padx=2, pady=2)
        ttk.Label(ssh_form, text="Contraseña:").grid(row=1, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(ssh_form, textvariable=self.ssh_password, show="*", width=15).grid(row=1, column=1, sticky=EW, padx=2, pady=2)
        ttk.Label(ssh_form, text="Ruta Clave:").grid(row=2, column=0, sticky=W, padx=2, pady=2)
        key_frame = ttk.Frame(ssh_form)
        key_frame.grid(row=2, column=1, sticky=EW)
        ttk.Entry(key_frame, textvariable=self.ssh_key_file, width=10).pack(side=LEFT, expand=True, fill=X)
        ttk.Button(key_frame, text="...", command=self._browse_ssh_key, width=3).pack(side=LEFT)

        # WMI
        wmi_label = ttk.Label(creds_frame, text="WMI (Windows):", style="Section.TLabel")
        wmi_label.pack(anchor=W, pady=(5,0))
        wmi_form = ttk.Frame(creds_frame)
        wmi_form.pack(fill=X, padx=10)
        ttk.Label(wmi_form, text="Usuario:").grid(row=0, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(wmi_form, textvariable=self.wmi_username, width=15).grid(row=0, column=1, sticky=EW, padx=2, pady=2)
        ttk.Label(wmi_form, text="Contraseña:").grid(row=1, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(wmi_form, textvariable=self.wmi_password, show="*", width=15).grid(row=1, column=1, sticky=EW, padx=2, pady=2)
        ttk.Label(wmi_form, text="Dominio:").grid(row=2, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(wmi_form, textvariable=self.wmi_domain, width=15).grid(row=2, column=1, sticky=EW, padx=2, pady=2)

        # SNMP
        snmp_label = ttk.Label(creds_frame, text="SNMP:", style="Section.TLabel")
        snmp_label.pack(anchor=W, pady=(5,0))
        snmp_form = ttk.Frame(creds_frame)
        snmp_form.pack(fill=X, padx=10)
        ttk.Label(snmp_form, text="Comunidad:").grid(row=0, column=0, sticky=W, padx=2, pady=2)
        ttk.Entry(snmp_form, textvariable=self.snmp_community, width=15).grid(row=0, column=1, sticky=EW, padx=2, pady=2)

        ssh_form.columnconfigure(1, weight=1)
        wmi_form.columnconfigure(1, weight=1)
        snmp_form.columnconfigure(1, weight=1)

        # Sección de Exportación
        export_frame = ttk.Labelframe(left_frame_container, text="Exportar Resultados", padding=10)
        export_frame.pack(fill=X, pady=10)
        self.export_button = ttk.Button(export_frame, text="Exportar Datos", command=self._export_data, state=DISABLED, style="Primary.TButton")
        self.export_button.pack(fill=X)

        # Panel Derecho: Resultados y Detalles
        right_frame_container = ttk.Frame(main_pane, padding=0) # No padding for container, let PanedWindow handle it
        right_frame_container.configure(borderwidth=1, relief="solid")
        main_pane.add(right_frame_container, weight=3)

        results_pane = ttk.PanedWindow(right_frame_container, orient=VERTICAL)
        results_pane.pack(fill=BOTH, expand=True)

        # Frame para la tabla de resultados y búsqueda
        results_table_frame = ttk.Frame(results_pane, padding=(10,10,10,0)) # Padding solo arriba y a los lados
        results_pane.add(results_table_frame, weight=2)

        # Frame de búsqueda con estilo moderno
        search_frame = ttk.Frame(results_table_frame)
        search_frame.pack(fill=X, pady=(0,5))
        ttk.Label(search_frame, text="Buscar:", font=('', 10)).pack(side=LEFT, padx=(0,5))
        search_entry = ttk.Entry(search_frame, textvariable=self.search_filter, font=('', 10))
        search_entry.pack(side=LEFT, fill=X, expand=True)

        # Configuración de la tabla de resultados
        style = ttk.Style()
        style.configure("Treeview", font=('', 10))  # Fuente base para la tabla
        style.configure("Treeview.Heading", font=('', 10, 'bold'))  # Fuente para encabezados

        # Definición de columnas con nombres en español
        columns = {
            "ip": ("IP", 120),
            "hostname": ("Hostname", 150),
            "mac": ("MAC", 150),
            "vendor": ("Fabricante", 150),
            "os": ("Sistema Operativo", 200),
            "ports": ("Puertos", 250) # Aumentar el ancho de la columna de puertos
        }

        # Crear Treeview con aspecto de tabla
        self.results_tree = ttk.Treeview(
            results_table_frame,
            columns=list(columns.keys()),
            show='headings',  # Solo mostrar los encabezados, sin la columna de árbol
            style="Treeview",
            height=20  # Altura aproximada en filas
        )

        # Configurar cada columna
        for col_id, (header, width) in columns.items():
            self.results_tree.heading(col_id, text=header, anchor=W)
            self.results_tree.column(col_id, width=width, stretch=True, anchor=W)

            # Añadir ordenamiento al hacer clic en el encabezado
            self.results_tree.heading(
                col_id,
                text=header,
                command=lambda _col=col_id: self._treeview_sort_column(_col, False)
            )

        # Configurar selección y estilo de la tabla
        self.results_tree.tag_configure('oddrow', background='#f0f0f0')  # Filas alternas
        self.results_tree.tag_configure('evenrow', background='#ffffff')

        # Scrollbars con estilo moderno
        tree_ysb = ttk.Scrollbar(results_table_frame, orient=VERTICAL, command=self.results_tree.yview)
        tree_xsb = ttk.Scrollbar(results_table_frame, orient=HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscroll=tree_ysb.set, xscroll=tree_xsb.set)

        # Empaquetar todo con el layout correcto
        tree_ysb.pack(side=RIGHT, fill=Y)
        tree_xsb.pack(side=BOTTOM, fill=X)
        self.results_tree.pack(fill=BOTH, expand=True)

        # Eventos
        self.results_tree.bind("<<TreeviewSelect>>", self._on_device_select)
        self.results_tree.bind('<Button-1>', self._on_click)
        self.results_tree.bind('<B1-Motion>', self._on_drag)
        self.results_tree.bind('<ButtonRelease-1>', self._on_release)

        # Frame para detalles del dispositivo
        details_frame = ttk.Labelframe(results_pane, text="Detalles del Dispositivo Seleccionado", padding=10)
        results_pane.add(details_frame, weight=1)

        self.details_notebook = ttk.Notebook(details_frame)
        self.details_notebook.pack(fill=BOTH, expand=True)

        self.general_details_text = scrolledtext.ScrolledText(self.details_notebook, wrap=WORD, state=DISABLED, height=10, relief="flat", borderwidth=0)
        self.ports_services_text = scrolledtext.ScrolledText(self.details_notebook, wrap=WORD, state=DISABLED, height=10, relief="flat", borderwidth=0)
        self.ssh_details_text = scrolledtext.ScrolledText(self.details_notebook, wrap=WORD, state=DISABLED, height=10, relief="flat", borderwidth=0)
        self.wmi_details_text = scrolledtext.ScrolledText(self.details_notebook, wrap=WORD, state=DISABLED, height=10, relief="flat", borderwidth=0)
        self.snmp_details_text = scrolledtext.ScrolledText(self.details_notebook, wrap=WORD, state=DISABLED, height=10, relief="flat", borderwidth=0) # Nueva pestaña SNMP

        self.details_notebook.add(self.general_details_text, text="General")
        self.details_notebook.add(self.ports_services_text, text="Puertos/Servicios")
        self.details_notebook.add(self.wmi_details_text, text="Info WMI")
        self.details_notebook.add(self.ssh_details_text, text="Info SSH")
        self.details_notebook.add(self.snmp_details_text, text="Info SNMP") # Añadir pestaña SNMP

    def _on_network_range_select(self, event=None):
        """
        Se llama cuando se selecciona un nuevo rango de red del Combobox.
        Actualiza self.network_range (StringVar que almacena el IP real) 
        basado en el texto mostrado seleccionado.
        """
        selected_display_text = self.combobox_selected_text_var.get()
        actual_ip_to_set = None

        for ip_range, display_text in self.available_network_details:
            if display_text == selected_display_text:
                actual_ip_to_set = ip_range
                break
        
        if actual_ip_to_set:
            self.network_range.set(actual_ip_to_set)
            logger.debug(f"Rango de red seleccionado: {actual_ip_to_set} (mostrado como: {selected_display_text})")
        else:
            logger.warning(f"No se pudo encontrar el IP real para el texto mostrado: {selected_display_text}. Usando el texto mostrado directamente como fallback.")
            # Fallback: intentar extraer el IP del texto mostrado "IP (Nombre)"
            parsed_ip = selected_display_text.split(" (")[0]
            self.network_range.set(parsed_ip)

    def _browse_ssh_key(self):
        """Abre un diálogo para seleccionar un archivo de clave SSH."""
        filepath = filedialog.askopenfilename(title="Seleccionar archivo de clave SSH")
        if filepath:
            self.ssh_key_file.set(filepath)

    def _update_scan_ui(self, scanning: bool, status_message: Optional[str] = None):
        """Actualiza la UI durante el escaneo."""
        if scanning:
            self.scan_button.config(state=DISABLED)
            self.export_button.config(state=DISABLED)
            self.scan_progress.start()
            if status_message:
                self.scan_status.set(status_message)
        else:
            self.scan_button.config(state=NORMAL)
            self.scan_progress.stop()
            if status_message:
                self.scan_status.set(status_message)
            else:
                self.scan_status.set(f"{len(self.scan_results)} dispositivos encontrados. Listo.")

            if self.scan_results:
                self.export_button.config(state=NORMAL)

    def _start_nmap_scan(self):
        """Inicia el escaneo Nmap en un hilo separado."""
        target = self.network_range.get().strip()
        if not target:
            messagebox.showwarning("Advertencia", "Por favor, ingrese un rango de red válido.")
            return

        self.scan_results.clear() # Limpiar resultados anteriores
        self._populate_results_tree() # Limpiar tabla
        self._clear_details_view() # Limpiar vistas de detalle

        self._update_scan_ui(True, "Escaneando red (Nmap)...")

        scan_thread = threading.Thread(target=self._perform_nmap_scan_thread, args=(target,), daemon=True)
        scan_thread.start()

    def _perform_nmap_scan_thread(self, target: str):
        """Lógica de escaneo Nmap que se ejecuta en el hilo."""
        try:
            # Inicializar la lista de resultados
            self.scan_results = []
            
            # Inicializar el contador de dispositivos encontrados
            devices_found = 0

            # 1. Escaneo rápido inicial para encontrar hosts activos
            self.after(0, lambda: self._update_scan_ui(True, "Buscando dispositivos activos..."))
            logger.debug("[DEBUG] Iniciando escaneo rápido para encontrar hosts activos")
            
            try:
                active_ips = self.nmap_scanner.quick_scan(target)
                logger.debug(f"[DEBUG] Escaneo rápido completado. IPs activas encontradas: {len(active_ips) if active_ips else 0}")
            except Exception as e:
                logger.error(f"[ERROR] Error en escaneo rápido: {e}", exc_info=True)
                self.after(0, lambda: messagebox.showerror(
                    "Error de Escaneo",
                    f"Error al realizar el escaneo rápido: {e}",
                    parent=self
                ))
                self.after(0, lambda: self._update_scan_ui(False, f"Error en escaneo rápido: {e}"))
                return

            if not active_ips:
                logger.debug("[DEBUG] No se encontraron dispositivos activos en el escaneo rápido")
                self.after(0, lambda: messagebox.showwarning(
                    "Escaneo Completado",
                    "No se encontraron dispositivos activos en la red especificada.",
                    parent=self
                ))
                self.after(0, lambda: self._update_scan_ui(False, "No se encontraron dispositivos."))
                return

            total_ips = len(active_ips)
            logger.debug(f"[DEBUG] Iniciando escaneo detallado de {total_ips} IPs activas")
            self.after(0, lambda: self._update_scan_ui(True, f"Encontrados {total_ips} dispositivos. Iniciando escaneo detallado..."))

            # 2. Escaneo detallado en paralelo
            from concurrent.futures import ThreadPoolExecutor, as_completed
            
            # Función para manejar el escaneo de un solo dispositivo
            def scan_single_device(ip):
                try:
                    logger.debug(f"[DEBUG] Iniciando escaneo detallado de {ip}")
                    device = self.nmap_scanner.detailed_scan(ip)
                    if device and hasattr(device, 'ip_address') and device.ip_address:
                        logger.debug(f"[DEBUG] Dispositivo encontrado: {device.ip_address}")
                        return device
                    else:
                        logger.warning(f"[WARN] No se pudo obtener información del dispositivo en {ip}")
                        return None
                except Exception as e:
                    logger.error(f"[ERROR] Error escaneando {ip}: {e}", exc_info=True)
                    return None
            
            # Usar un máximo de 5 workers para no sobrecargar el sistema
            max_workers = min(5, len(active_ips))
            logger.debug(f"[DEBUG] Usando {max_workers} workers para escaneo paralelo")
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Iniciar todos los escaneos
                future_to_ip = {executor.submit(scan_single_device, ip): ip for ip in active_ips}
                
                # Procesar resultados conforme van llegando
                completed = 0
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    completed += 1
                    
                    try:
                        device = future.result()
                        if device:
                            # Usar el método on_device_found para manejar la actualización de la UI
                            self.after(0, lambda d=device: self.on_device_found(d))
                            devices_found += 1
                            logger.debug(f"[DEBUG] Dispositivo procesado exitosamente: {device.ip_address}")
                        else:
                            logger.warning(f"[WARN] No se pudo obtener información del dispositivo en {ip}")
                    except Exception as e:
                        logger.error(f"[ERROR] Error procesando resultado de {ip}: {e}", exc_info=True)
                    
                    # Actualizar progreso
                    progress = (completed / total_ips) * 100
                    self.after(0, lambda p=progress, c=completed, t=total_ips, d=devices_found: 
                              self._update_scan_ui(True, f"Escaneando... {c}/{t} ({p:.1f}%), {d} dispositivos encontrados"))

            # 3. Finalizar y actualizar UI
            logger.debug(f"[DEBUG] Escaneo completado. Dispositivos encontrados: {devices_found}")
            
            if devices_found > 0:
                self._count_device_types()
                logger.info(f"[INFO] Escaneo completado. Encontrados {devices_found} dispositivos.")
                
                # Si algún escaneo detallado está habilitado, iniciar escaneos detallados
                if self.snmp_detailed_scan_enabled.get() or \
                   self.wmi_scan_enabled.get() or \
                   self.ssh_detailed_scan_enabled.get():
                    logger.debug("[DEBUG] Iniciando escaneos detallados (SNMP, WMI y/o SSH según selección)")
                    self._start_automatic_detailed_scans()
                else:
                    logger.debug("[DEBUG] No hay escaneos detallados habilitados. Finalizando después de Nmap.")
                    self.after(0, lambda: self._update_scan_ui(False, f"Escaneo Nmap completado. {devices_found} dispositivos encontrados."))
                    self.after(0, self._save_scan_to_db) # Guardar resultados de Nmap si no hay escaneos detallados automáticos
            else:
                logger.warning("[WARN] No se encontraron dispositivos en el escaneo detallado")
                self.after(0, lambda: self._update_scan_ui(False, "No se encontraron dispositivos con información detallada."))

        except Exception as e:
            error_msg = f"[ERROR] Error crítico durante el escaneo: {e}"
            logger.error(error_msg, exc_info=True)
            
            # Mostrar mensaje de error en la interfaz
            self.after(0, lambda: messagebox.showerror(
                "Error de Escaneo",
                f"Ocurrió un error durante el escaneo: {e}",
                parent=self
            ))
            self.after(0, lambda: self._update_scan_ui(False, f"Error durante el escaneo: {str(e)}"))
            
            # Intentar continuar con los dispositivos encontrados hasta el momento
            if hasattr(self, 'scan_results') and self.scan_results:
                logger.warning(f"[WARN] Continuando con {len(self.scan_results)} dispositivos encontrados antes del error")
                self.after(0, lambda: self._update_scan_ui(False, f"Escaneo parcial completado con errores. {len(self.scan_results)} dispositivos encontrados."))
                self._populate_results_tree()

    def _count_device_types(self):
        """Cuenta los dispositivos por tipo y marca si tienen puertos relevantes."""
        self.windows_devices_count = 0
        self.linux_devices_count = 0
        self.snmp_devices_count = 0

        for device in self.scan_results:
            os_lower = device.get_os().lower() if device.get_os() else ""
            device.has_wmi_potential = False # Usar un nombre más descriptivo
            device.has_ssh_potential = False
            device.has_snmp_potential = False

            if "windows" in os_lower:
                self.windows_devices_count += 1
                device.has_wmi_potential = True

            if any(x in os_lower for x in ["linux", "unix", "ubuntu", "debian", "centos", "fedora", "mac", "os x"]):
                self.linux_devices_count += 1
                device.has_ssh_potential = True

            # Nmap puede detectar el servicio SNMP en otros puertos, pero 161/udp es el estándar
            if 161 in device.get_open_ports().get('udp', {}):
                self.snmp_devices_count += 1
                device.has_snmp_potential = True
            elif any('snmp' in service_info.get('name','').lower() for port_info in device.get_open_ports().values() for service_info in port_info.values()):
                self.snmp_devices_count += 1
                device.has_snmp_potential = True


    def _populate_results_tree(self):
        """Actualiza el árbol de resultados con los dispositivos encontrados."""
        try:
            logger.debug(f"[DEBUG] Iniciando actualización del árbol de resultados")
            
            # Verificar que el TreeView existe
            if not hasattr(self, 'results_tree') or not self.results_tree:
                logger.error("[ERROR] El TreeView de resultados no está inicializado")
                return
            
            # Limpiar árbol existente
            logger.debug("[DEBUG] Limpiando árbol de resultados existente")
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)

            # Verificar que hay dispositivos para mostrar
            if not hasattr(self, 'scan_results') or not self.scan_results:
                logger.debug("[DEBUG] No hay dispositivos en self.scan_results para mostrar")
                return
                
            logger.debug(f"[DEBUG] Intentando mostrar {len(self.scan_results)} dispositivos")
            logger.debug(f"[DEBUG] Dispositivos en scan_results: {[d.ip_address for d in self.scan_results if hasattr(d, 'ip_address')]}")

            # Insertar dispositivos en el Treeview
            for i, device in enumerate(self.scan_results):
                try:
                    # Validación básica del dispositivo
                    if not device or not hasattr(device, 'ip_address') or not device.ip_address:
                        logger.warning(f"[WARN] Dispositivo inválido o sin IP en la posición {i}, omitiendo...")
                        continue
                    
                    # Formatear puertos con más detalles
                    ports_str = "N/A"
                    if hasattr(device, 'services') and device.services:
                        port_details = []
                        for port, service in device.services.items():
                            if not port or not service:
                                continue
                            if isinstance(service, dict):
                                service_name = service.get('name', 'unknown')
                                service_state = service.get('state', 'unknown')
                                port_details.append(f"{port}/{service_name}/{service_state}")
                        
                        if port_details:
                            ports_str = ", ".join(sorted(port_details, key=lambda x: int(x.split('/')[0]) if x.split('/')[0].isdigit() else 0))
                    elif hasattr(device, 'open_ports') and device.open_ports:
                        # Si no hay servicios pero sí puertos abiertos
                        ports_str = ", ".join(str(p) for p in device.open_ports if p)

                    # Obtener información del dispositivo con valores por defecto seguros
                    ip_address = getattr(device, 'ip_address', 'N/A')
                    hostname = str(getattr(device, 'hostname', 'N/A'))
                    mac_address = str(getattr(device, 'mac_address', 'N/A'))
                    vendor = str(getattr(device, 'vendor', 'N/A'))
                    
                    # Obtener información del sistema operativo de forma segura
                    os_info = "N/A"
                    try:
                        if hasattr(device, 'os_info') and isinstance(device.os_info, dict):
                            os_info = device.os_info.get('name', 
                                                      device.os_info.get('os',
                                                      device.os_info.get('description_snmp', 
                                                                      device.os_info.get('caption', 'N/A'))))
                        elif hasattr(device, 'get_os') and callable(device.get_os):
                            os_info = device.get_os() or "N/A"
                    except Exception as e:
                        logger.warning(f"[WARN] Error al obtener información del SO para {ip_address}: {e}")
                        os_info = "N/A"

                    # Preparar los valores para insertar
                    values = (
                        ip_address,
                        hostname if hostname != 'N/A' else ip_address,  # Mostrar IP si no hay hostname
                        mac_address,
                        vendor,
                        os_info,
                        ports_str
                    )
                    
                    # Insertar en el árbol
                    try:
                        self.results_tree.insert('', 'end', values=values, tags=('oddrow' if i % 2 else 'evenrow'))
                        logger.debug(f"[DEBUG] Dispositivo agregado al árbol: {ip_address} - {hostname}")
                    except Exception as e:
                        logger.error(f"[ERROR] Error al insertar dispositivo en el árbol: {e}")
                        continue
                    
                except Exception as e:
                    logger.error(f"[ERROR] Error al procesar el dispositivo en la posición {i}: {e}", exc_info=True)
                    continue
                    
            logger.debug("[DEBUG] Actualización del árbol de resultados completada exitosamente")
            
            # Forzar actualización de la interfaz
            self.update_idletasks()
            
        except Exception as e:
            error_msg = f"[ERROR] Error crítico en _populate_results_tree: {str(e)}"
            logger.error(error_msg, exc_info=True)
            messagebox.showerror("Error", f"No se pudieron cargar los dispositivos: {str(e)}")
            
            # Intentar mostrar información de depuración
            try:
                debug_info = {
                    'has_results': hasattr(self, 'scan_results'),
                    'results_count': len(self.scan_results) if hasattr(self, 'scan_results') else 0,
                    'results_type': type(self.scan_results).__name__ if hasattr(self, 'scan_results') else 'N/A',
                    'results_sample': str([getattr(d, 'ip_address', 'No IP') for d in self.scan_results[:3]]) + ('...' if len(self.scan_results) > 3 else '') if hasattr(self, 'scan_results') and self.scan_results else 'N/A'
                }
                logger.debug(f"[DEBUG] Información de depuración: {debug_info}")
            except Exception as debug_e:
                logger.error(f"[ERROR] Error al recopilar información de depuración: {debug_e}")

    def _apply_filter(self, *args):
        """Filtra los resultados del Treeview según el texto de búsqueda."""
        search_term = self.search_filter.get().lower()
        if not search_term:
            self.filtered_results = self.scan_results[:]
        else:
            self.filtered_results = [
                dev for dev in self.scan_results
                if search_term in str(dev.ip_address).lower() or \
                   search_term in str(dev.hostname).lower() or \
                   search_term in str(dev.mac_address).lower() or \
                   search_term in str(dev.vendor).lower() or \
                   search_term in str(dev.get_os()).lower()
            ]
        self._populate_results_tree()

    def _on_device_select(self, event=None):
        """Maneja la selección de un dispositivo en el Treeview."""
        try:
            selected_item = self.results_tree.focus()
            if not selected_item:
                self.selected_device_ip = None
                self._clear_details_view()
                return

            item_values = self.results_tree.item(selected_item, "values")
            if not item_values or len(item_values) == 0:
                logger.warning("No se encontraron valores para el ítem seleccionado")
                self.selected_device_ip = None
                self._clear_details_view()
                return

            selected_ip = item_values[0].strip() if item_values[0] else None
            if not selected_ip:
                logger.warning("No se pudo obtener la dirección IP del ítem seleccionado")
                self.selected_device_ip = None
                self._clear_details_view()
                return

            self.selected_device_ip = selected_ip
            logger.debug(f"Dispositivo seleccionado - IP: {self.selected_device_ip}")
            
            # Buscar el dispositivo por IP en los resultados del escaneo
            found_device = None
            for dev in self.scan_results:
                if dev.ip_address == self.selected_device_ip:
                    found_device = dev
                    break
            
            if found_device:
                logger.debug(f"Dispositivo encontrado: {found_device.ip_address} - {found_device.hostname}")
                self._update_device_details_view(found_device)
            else:
                logger.warning(f"No se encontró el dispositivo con IP {self.selected_device_ip} en los resultados del escaneo")
                logger.debug(f"Dispositivos en scan_results: {[d.ip_address for d in self.scan_results]}")
                self._clear_details_view()
                
        except Exception as e:
            logger.error(f"Error al seleccionar dispositivo: {e}", exc_info=True)
            self.selected_device_ip = None
            self._clear_details_view()

    def _clear_details_view(self):
        """Limpia todas las pestañas de detalles."""
        text_widgets = [
            self.general_details_text, self.ports_services_text,
            self.wmi_details_text, self.ssh_details_text, self.snmp_details_text
        ]
        for text_widget in text_widgets:
            text_widget.config(state=NORMAL)
            text_widget.delete(1.0, END)
            text_widget.config(state=DISABLED)

    def _update_text_widget(self, widget, content):
        """Actualiza un widget ScrolledText con el contenido dado."""
        widget.config(state=NORMAL)
        widget.delete(1.0, END)
        if isinstance(content, (dict, list)):
            import json
            widget.insert(END, json.dumps(content, indent=2, ensure_ascii=False))
        elif content:
            widget.insert(END, str(content))
        else:
            widget.insert(END, "No hay datos disponibles.")
        widget.config(state=DISABLED)

    def _update_device_details_view(self, device: Device):
        """Actualiza las pestañas de detalles con la información del dispositivo."""
        if not device:
            self._clear_details_view()
            return

        # Pestaña General
        general_info = f"""Información General:
  - IP: {device.ip_address}
  - Hostname: {device.hostname or 'N/A'}
  - MAC: {device.mac_address or 'N/A'}
  - Vendor: {device.vendor or 'N/A'}
  - OS: {device.os_info.get('name', 'N/A')}
  - Tipo: {device.type}
  - Último escaneo: {device.last_scan or 'N/A'}
  - Estado: {device.status}
"""
        if device.scan_error:
            general_info += f"\nError en el último escaneo: {device.scan_error}"

        self._update_text_widget(self.general_details_text, general_info)

        # Pestaña Puertos/Servicios
        services_info = "Puertos y Servicios:\n"
        if device.services:
            for port, service_info in device.services.items():
                protocol = service_info.get('protocol', 'tcp')  # Default to tcp if not specified
                name = service_info.get('name', '').strip()
                version = service_info.get('version', '').strip()
                state = service_info.get('state', 'open').lower()
                product = service_info.get('product', '').strip()
                
                # Skip if port is not open
                if state != 'open':
                    continue
                
                # Build service string
                service_str = f"  - {port}/{protocol}"
                
                # Add service name if available
                if name and name != 'unknown':
                    service_str += f": {name}"
                
                # Add version if available
                if version:
                    service_str += f" {version}"
                
                # Add product if different from name
                if product and product.lower() != name.lower():
                    service_str += f" ({product})"
                
                services_info += service_str + "\n"
                
        if services_info == "Puertos y Servicios:\n":
            services_info += "  No se encontraron puertos abiertos.\n"
        self._update_text_widget(self.ports_services_text, services_info)

        # Pestaña Hardware
        hardware_info = "Información de Hardware:\n"
        if device.hardware_info:
            for key, value in device.hardware_info.items():
                hardware_info += f"  - {key.replace('_', ' ').capitalize()}: {value}\n"
        else:
            hardware_info += "  No disponible.\n"
        self._update_text_widget(self.wmi_details_text, hardware_info)

        # Pestaña Info SNMP
        snmp_info = "Información SNMP:\n"

        # Información del sistema
        snmp_info += "\nInformación del Sistema:\n"
        if device.os_info:
            if 'description_snmp' in device.os_info:
                snmp_info += f"  - Descripción: {device.os_info['description_snmp']}\n"
            if 'name' in device.os_info:
                snmp_info += f"  - Sistema Operativo: {device.os_info['name']}\n"
            if 'uptime_snmp' in device.os_info:
                snmp_info += f"  - Tiempo de actividad: {device.os_info['uptime_snmp']}\n"
            if 'location' in device.os_info:
                snmp_info += f"  - Ubicación: {device.os_info['location']}\n"
            if 'contact' in device.os_info:
                snmp_info += f"  - Contacto: {device.os_info['contact']}\n"

        # Información de hardware
        snmp_info += "\nInformación de Hardware:\n"
        if device.hardware_info:
            if 'total_memory_kb' in device.hardware_info:
                mem_total = int(device.hardware_info['total_memory_kb']) / 1024
                snmp_info += f"  - Memoria Total: {mem_total:.2f} MB\n"
            if 'available_memory_kb' in device.hardware_info:
                mem_avail = int(device.hardware_info['available_memory_kb']) / 1024
                snmp_info += f"  - Memoria Disponible: {mem_avail:.2f} MB\n"
            if 'memory_usage_percent' in device.hardware_info:
                snmp_info += f"  - Uso de Memoria: {device.hardware_info['memory_usage_percent']}\n"
            if 'cpu_load' in device.hardware_info:
                snmp_info += f"  - Carga de CPU: {device.hardware_info['cpu_load']}%\n"
            if 'running_processes' in device.hardware_info:
                snmp_info += f"  - Procesos en ejecución: {device.hardware_info['running_processes']}\n"
            if 'system_users' in device.hardware_info:
                snmp_info += f"  - Usuarios del sistema: {device.hardware_info['system_users']}\n"

        # Información de interfaces de red
        snmp_info += "\nInterfaces de Red:\n"
        if 'interfaces' in device.network_info:
            for i, interface in enumerate(device.network_info['interfaces']):
                if 'description' in interface:
                    snmp_info += f"  - Interfaz {i+1}: {interface['description']}\n"
                    if 'mac_address' in interface:
                        snmp_info += f"    MAC: {interface['mac_address']}\n"
                    if 'ip_addresses' in interface and interface['ip_addresses']:
                        snmp_info += f"    IPs: {', '.join(interface['ip_addresses'])}\n"
                    if 'admin_status' in interface:
                        snmp_info += f"    Estado Admin: {interface['admin_status']}\n"
                    if 'oper_status' in interface:
                        snmp_info += f"    Estado Operativo: {interface['oper_status']}\n"
                    if 'speed' in interface:
                        try:
                            speed_mbps = int(interface['speed']) / 1000000
                            snmp_info += f"    Velocidad: {speed_mbps:.0f} Mbps\n"
                        except (ValueError, TypeError):
                            snmp_info += f"    Velocidad: {interface['speed']}\n"

        # Si no hay información SNMP
        if not device.snmp_info or (len(device.os_info) == 0 and len(device.hardware_info) == 0 and len(device.network_info) == 0):
            snmp_info += "  No disponible o no escaneado.\n"

        self._update_text_widget(self.snmp_details_text, snmp_info)

        # Pestaña Info SSH
        ssh_info_str = "Información SSH:\n"
        if device.ssh_specific_info and device.ssh_specific_info.get("Estado") != "Desconocido" and not device.ssh_specific_info.get("error"):
            for key, value in device.ssh_specific_info.items():
                ssh_info_str += f"  - {key.replace('_', ' ').capitalize()}: {value}\n"
        elif device.ssh_specific_info and device.ssh_specific_info.get("error"):
            ssh_info_str += f"  Error: {device.ssh_specific_info['error']}\n"
        else:
            ssh_info_str += "  No disponible o no escaneado.\n"
        self._update_text_widget(self.ssh_details_text, ssh_info_str)

        # Pestaña Info WMI
        wmi_info_str = "Información WMI:\n"
        if device.wmi_specific_info and device.wmi_specific_info.get("Estado") != "Desconocido" and not device.wmi_specific_info.get("error"):
            for key, value in device.wmi_specific_info.items():
                wmi_info_str += f"  - {key.replace('_', ' ').capitalize()}: {value}\n"
        elif device.wmi_specific_info and device.wmi_specific_info.get("error"):
            wmi_info_str += f"  Error: {device.wmi_specific_info['error']}\n"
        else:
            wmi_info_str += "  No disponible o no escaneado.\n"
        self._update_text_widget(self.wmi_details_text, wmi_info_str)


    # Removed _save_scan_to_db from here, moved to _start_automatic_detailed_scans
    def _save_scan_to_db(self):
        """Guarda los resultados del escaneo en la base de datos."""
        try:
            if not self.scan_results:
                logging.warning("No hay dispositivos para guardar en la base de datos.")
                return

            logging.info(f"Guardando {len(self.scan_results)} dispositivos en la base de datos.")

            # Crear reporte de red
            report = NetworkReport(
                target=self.network_range.get(),
                timestamp=int(time.time()),
                engine_info="Nmap Scanner"
            )

            # Añadir dispositivos al reporte
            for device in self.scan_results:
                report.add_device(device)

            # Guardar en la base de datos
            self.inventory_manager.save_report(report)
            logging.info("Reporte guardado exitosamente en la base de datos.")

            # Optional: Show a success message in the UI
        except Exception as e:
            logging.error(f"Error inesperado al guardar en la base de datos: {str(e)}")
            logging.debug(f"Detalles del error:", exc_info=True)
            messagebox.showerror(
                "Error al Guardar",
                f"No se pudieron guardar los resultados en la base de datos:\n{str(e)}"
            )

    def _export_data(self):
        """Exporta los datos del escaneo a un formato seleccionado por el usuario."""
        if not self.scan_results:
            messagebox.showwarning("Sin Datos", "No hay datos para exportar.", parent=self)
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            title="Guardar Reporte Como"
        )
        if not file_path:
            return

        # El target para el reporte puede ser el rango de red escaneado
        report_target = self.network_range.get()
        file_ext = os.path.splitext(file_path)[1].lower()

        try:
            if file_ext == ".html":
                html_exporter().save_report(self.scan_results, file_path, target=report_target)
            else:
                messagebox.showerror("Error de Formato", f"Formato de archivo no soportado: {file_ext}. Por favor, guarde como .html.", parent=self)
                return

            messagebox.showinfo("Exportación Exitosa", f"Datos exportados correctamente a:\n{file_path}", parent=self)
            logger.info(f"Datos exportados a {file_path}")
        except Exception as e:
            messagebox.showerror("Error de Exportación", f"No se pudo exportar el archivo: {e}", parent=self)
            logger.error(f"Error al exportar datos a {file_path}: {e}", exc_info=True)

    def _on_closing(self):
        """Maneja el evento de cierre de la ventana."""
        if messagebox.askokcancel("Salir", "¿Está seguro de que desea salir?", parent=self):
            logger.info("Cerrando la aplicación.")
            if self.inventory_manager:
                self.inventory_manager.close() # Cerrar conexión a la base de datos
            self.destroy()

    def _treeview_sort_column(self, col, reverse):
        l = [(self.results_tree.set(k, col), k) for k in self.results_tree.get_children('')]
        l.sort(key=lambda t: t[0], reverse=reverse)

        for index, (val, k) in enumerate(l):
            self.results_tree.move(k, '', index)

        self.results_tree.heading(col, command=lambda _col=col: self._treeview_sort_column(_col, not reverse))

    def _on_click(self, event):
        self._drag_data["x"] = event.x
        self._drag_data["y"] = event.y
        self._drag_data["item"] = self.results_tree.identify_row(event.y)

    def _on_drag(self, event):
        dx = event.x - self._drag_data["x"]
        dy = event.y - self._drag_data["y"]
        self._drag_data["x"] = event.x
        self._drag_data["y"] = event.y
        item = self._drag_data["item"]
        if item:
            self.results_tree.move(item, '', self.results_tree.index(item) + dy // 20)

    def _on_release(self, event):
        self._drag_data["item"] = None

    def on_device_found(self, device: Device):
        """Callback cuando se encuentra un dispositivo"""
        try:
            if not device or not hasattr(device, 'ip_address') or not device.ip_address:
                logger.warning("[WARN] Dispositivo inválido o sin dirección IP")
                logger.warning(f"[WARN] Tipo de dispositivo: {type(device)}")
                logger.warning(f"[WARN] Atributos del dispositivo: {dir(device) if device else 'None'}")
                return

            logger.debug(f"[DEBUG] Dispositivo encontrado: IP={device.ip_address}, Hostname={getattr(device, 'hostname', 'N/A')}, Tipo={type(device)}")
            
            # Make sure we're working with the main thread's scan_results
            if not hasattr(self, 'scan_results'):
                self.scan_results = []
            
            # Verificar si el dispositivo ya está en los resultados
            existing_device = None
            existing_index = -1
            for i, d in enumerate(self.scan_results):
                if hasattr(d, 'ip_address') and d.ip_address == device.ip_address:
                    existing_device = d
                    existing_index = i
                    logger.debug(f"[DEBUG] Dispositivo existente encontrado en índice {i}")
                    break
            
            if existing_device is not None and existing_index >= 0:
                # Actualizar el dispositivo existente
                logger.debug(f"[DEBUG] Actualizando dispositivo existente: {device.ip_address}")
                try:
                    # Create a new device with updated attributes
                    updated_device = Device(ip_address=device.ip_address, hostname=getattr(device, 'hostname', ''))
                    updated_device.__dict__.update(device.__dict__)
                    self.scan_results[existing_index] = updated_device
                    logger.debug(f"[DEBUG] Dispositivo actualizado: {device.ip_address}")
                except Exception as e:
                    logger.error(f"[ERROR] Error al actualizar dispositivo: {e}", exc_info=True)
            else:
                # Agregar el nuevo dispositivo
                try:
                    logger.debug(f"[DEBUG] Agregando nuevo dispositivo: {device.ip_address}")
                    new_device = Device(ip_address=device.ip_address, hostname=getattr(device, 'hostname', ''))
                    new_device.__dict__.update(device.__dict__)
                    self.scan_results.append(new_device)
                    logger.debug(f"[DEBUG] Nuevo dispositivo agregado: {device.ip_address}")
                except Exception as e:
                    logger.error(f"[ERROR] Error al agregar dispositivo: {e}", exc_info=True)
            
            logger.debug(f"[DEBUG] Total de dispositivos en scan_results: {len(self.scan_results)}")
            
            # Actualizar la tabla de resultados
            def update_ui():
                try:
                    logger.debug("[DEBUG] Iniciando actualización de UI...")
                    logger.debug(f"[DEBUG] Dispositivos antes de actualizar UI: {[d.ip_address for d in self.scan_results] if hasattr(self, 'scan_results') else 'No hay scan_results'}")
                    self._populate_results_tree()
                    self._update_scan_ui(True, f"Dispositivo encontrado: {device.ip_address} - {getattr(device, 'hostname', 'Sin nombre')}")
                    logger.debug("[DEBUG] UI actualizada correctamente")
                except Exception as e:
                    logger.error(f"[ERROR] Error al actualizar la UI: {e}", exc_info=True)
            
            # Asegurarse de que la actualización de la UI se haga en el hilo principal
            self.after(0, update_ui)
            
        except Exception as e:
            logger.error(f"[ERROR] Error en on_device_found: {e}", exc_info=True)

    def _create_menu_bar(self):
        """Crea la barra de menú principal de la aplicación."""
        menubar = tk.Menu(self)
        self.config(menu=menubar)

        # Menú Archivo
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Archivo", menu=file_menu)
        file_menu.add_command(label="Nuevo escaneo", command=self._reset_scan)
        file_menu.add_command(label="Guardar resultados", command=self._save_results)
        file_menu.add_command(label="Cargar resultados guardados", command=self._load_saved_results)
        file_menu.add_separator()
        file_menu.add_command(label="Importar resultados", command=self._import_results)

        # Submenú de exportación
        export_menu = tk.Menu(file_menu, tearoff=0)
        file_menu.add_cascade(label="Exportar", menu=export_menu)
        # Eliminadas opciones CSV y JSON
        # export_menu.add_command(label="Exportar a CSV", command=lambda: self._export_results("csv"))
        # export_menu.add_command(label="Exportar a JSON", command=lambda: self._export_results("json"))
        export_menu.add_command(label="Exportar a HTML", command=lambda: self._export_results("html"))
        export_menu.add_command(label="Exportar a PDF", command=lambda: self._export_results("pdf"))
        export_menu.add_separator()
        export_menu.add_command(label="Informe detallado", command=self._generate_detailed_report)
        export_menu.add_command(label="Informe de seguridad", command=self._generate_security_report)

        file_menu.add_separator()
        file_menu.add_command(label="Salir", command=self._on_closing)

        # Menú Escaneo
        scan_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Escaneo", menu=scan_menu)
        scan_menu.add_command(label="Iniciar escaneo", command=self._start_nmap_scan)
        scan_menu.add_command(label="Detener escaneo", command=self._stop_scan)
        scan_menu.add_separator()
        scan_menu.add_command(label="Configuración de escaneo", command=self._configure_scan_options)
        scan_menu.add_command(label="Escaneo programado", command=self._schedule_scan)
        scan_menu.add_separator()
        scan_menu.add_command(label="Escaneo rápido", command=self._quick_scan)
        scan_menu.add_command(label="Escaneo completo", command=self._full_scan)
        scan_menu.add_command(label="Escaneo personalizado", command=self._custom_scan)

        # Menú Ver
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ver", menu=view_menu)
        view_menu.add_command(label="Topología de red", command=self._show_topology)
        view_menu.add_command(label="Mapa de red interactivo", command=self._show_interactive_map)
        view_menu.add_command(label="Estadísticas", command=self._show_statistics)
        view_menu.add_command(label="Gráficos", command=self._show_charts)
        view_menu.add_command(label="Historial de cambios", command=self._show_change_history)
        view_menu.add_separator()
        view_menu.add_command(label="Filtrar resultados", command=self._filter_results)
        view_menu.add_command(label="Ordenar resultados", command=self._sort_results)
        view_menu.add_separator()
        view_menu.add_command(label="Refrescar", command=self._refresh_view)

        # Menú Herramientas
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Herramientas", menu=tools_menu)

        # Submenú de análisis de seguridad
        security_menu = tk.Menu(tools_menu, tearoff=0)
        tools_menu.add_cascade(label="Análisis de seguridad", menu=security_menu)
        security_menu.add_command(label="Ejecutar análisis", command=self._run_security_analysis)
        security_menu.add_command(label="Configurar análisis", command=self._configure_security_analysis)
        security_menu.add_command(label="Ver vulnerabilidades", command=self._view_vulnerabilities)
        security_menu.add_command(label="Recomendaciones de seguridad", command=self._show_security_recommendations)

        # Submenú de monitoreo
        monitoring_menu = tk.Menu(tools_menu, tearoff=0)
        tools_menu.add_cascade(label="Monitoreo", menu=monitoring_menu)
        monitoring_menu.add_command(label="Iniciar monitoreo en tiempo real", command=self._start_monitoring)
        monitoring_menu.add_command(label="Detener monitoreo", command=self._stop_monitoring)
        monitoring_menu.add_command(label="Configurar monitoreo", command=self._configure_monitoring)
        monitoring_menu.add_command(label="Ver historial de alertas", command=self._view_alert_history)

        # Submenú de alertas
        alerts_menu = tk.Menu(tools_menu, tearoff=0)
        tools_menu.add_cascade(label="Alertas", menu=alerts_menu)
        alerts_menu.add_command(label="Configurar alertas", command=self._configure_alerts)
        alerts_menu.add_command(label="Crear regla personalizada", command=self._create_custom_alert_rule)
        alerts_menu.add_command(label="Gestionar reglas", command=self._manage_alert_rules)
        alerts_menu.add_command(label="Configurar notificaciones", command=self._configure_notifications)

        tools_menu.add_separator()
        tools_menu.add_command(label="Gestión de credenciales", command=self._manage_credentials)
        tools_menu.add_command(label="Conexión SSH", command=self._connect_ssh)
        tools_menu.add_command(label="Conexión RDP", command=self._connect_rdp)
        tools_menu.add_command(label="Abrir interfaz web", command=self._open_web_interface)
        tools_menu.add_separator()
        tools_menu.add_command(label="Ping", command=self._ping_device)
        tools_menu.add_command(label="Traceroute", command=self._traceroute)
        tools_menu.add_command(label="Escaneo de puertos", command=self._port_scan)

        # Menú Inventario
        inventory_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Inventario", menu=inventory_menu)
        inventory_menu.add_command(label="Ver inventario completo", command=self._show_inventory)
        inventory_menu.add_command(label="Buscar dispositivo", command=self._search_device)
        inventory_menu.add_separator()
        inventory_menu.add_command(label="Gestionar etiquetas", command=self._manage_tags)
        inventory_menu.add_command(label="Categorizar dispositivos", command=self._categorize_devices)
        inventory_menu.add_command(label="Añadir dispositivo manualmente", command=self._add_device_manually)
        inventory_menu.add_command(label="Editar dispositivo", command=self._edit_device)
        inventory_menu.add_separator()
        inventory_menu.add_command(label="Exportar inventario", command=self._export_inventory)
        inventory_menu.add_command(label="Importar inventario", command=self._import_inventory)
        inventory_menu.add_separator()
        inventory_menu.add_command(label="Gestionar base de datos", command=self._manage_database)

        # Menú Ayuda
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Ayuda", menu=help_menu)
        help_menu.add_command(label="Manual de usuario", command=self._show_user_manual)
        help_menu.add_command(label="Guía rápida", command=self._show_quick_guide)
        help_menu.add_command(label="Tutoriales", command=self._show_tutorials)
        help_menu.add_command(label="Preguntas frecuentes", command=self._show_faq)
        help_menu.add_separator()
        help_menu.add_command(label="Acerca de", command=self._show_about)
        help_menu.add_command(label="Verificar actualizaciones", command=self._check_updates)
        help_menu.add_separator()
        help_menu.add_command(label="Reportar problema", command=self._report_issue)

    # Métodos adicionales para las nuevas opciones del menú
    def _save_results(self):
        """Guarda los resultados del escaneo actual."""
        if not self.scan_results:
            messagebox.showwarning("Guardar", "No hay resultados para guardar.")
            return

        file_path = filedialog.asksaveasfilename(
            title="Guardar resultados",
            defaultextension=".json",
            filetypes=[("Archivos JSON", "*.json"), ("Todos los archivos", "*.*")]
        )
        if file_path:
            try:
                # La exportación directa a JSON se ha eliminado, pero si se quisiera guardar
                # el estado de los dispositivos para recargar, se podría hacer aquí.
                messagebox.showinfo("Guardar", f"Resultados guardados exitosamente en {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Error al guardar resultados: {e}")

    def _load_saved_results(self):
        """Carga resultados guardados previamente."""
        file_path = filedialog.askopenfilename(
            title="Cargar resultados guardados",
            filetypes=[("Archivos JSON", "*.json"), ("Todos los archivos", "*.*")]
        )
        if file_path:
            try:
                # Aquí iría la lógica para cargar resultados
                messagebox.showinfo("Cargar", "Carga de resultados guardados no implementada aún.")
            except Exception as e:
                messagebox.showerror("Error", f"Error al cargar resultados: {e}")

    def _generate_detailed_report(self):
        """Genera un informe detallado de los dispositivos escaneados."""
        if not self.scan_results:
            messagebox.showwarning("Informe", "No hay resultados para generar un informe.")
            return

        # Aquí iría la lógica para generar el informe detallado
        messagebox.showinfo("Informe", "Generación de informe detallado no implementada aún.")

    def _generate_security_report(self):
        """Genera un informe de seguridad de los dispositivos escaneados."""
        if not self.scan_results:
            messagebox.showwarning("Informe", "No hay resultados para generar un informe de seguridad.")
            return

        # Aquí iría la lógica para generar el informe de seguridad
        messagebox.showinfo("Informe", "Generación de informe de seguridad no implementada aún.")

    def _stop_scan(self):
        """Detiene el escaneo en curso."""
        # Aquí iría la lógica para detener el escaneo
        messagebox.showinfo("Escaneo", "Detención de escaneo no implementada aún.")

    def _schedule_scan(self):
        """Programa un escaneo para ejecutarse en un momento específico."""
        # Aquí iría la lógica para programar un escaneo
        messagebox.showinfo("Escaneo", "Programación de escaneo no implementada aún.")

    def _quick_scan(self):
        """Realiza un escaneo rápido de la red."""
        # Aquí iría la lógica para un escaneo rápido
        messagebox.showinfo("Escaneo", "Escaneo rápido no implementado aún.")

    def _full_scan(self):
        """Realiza un escaneo completo y detallado de la red."""
        # Aquí iría la lógica para un escaneo completo
        messagebox.showinfo("Escaneo", "Escaneo completo no implementado aún.")

    def _custom_scan(self):
        """Permite configurar un escaneo personalizado."""
        # Aquí iría la lógica para un escaneo personalizado
        messagebox.showinfo("Escaneo", "Escaneo personalizado no implementado aún.")

    def _show_interactive_map(self):
        """Muestra un mapa interactivo de la red."""
        if not self.scan_results:
            messagebox.showwarning("Mapa", "No hay resultados para mostrar el mapa.")
            return

        # Aquí iría la lógica para mostrar el mapa interactivo
        messagebox.showinfo("Mapa", "Visualización de mapa interactivo no implementada aún.")

    def _show_charts(self):
        """Muestra gráficos y visualizaciones de los datos de red."""
        if not self.scan_results:
            messagebox.showwarning("Gráficos", "No hay resultados para mostrar gráficos.")
            return

        # Aquí iría la lógica para mostrar gráficos
        messagebox.showinfo("Gráficos", "Visualización de gráficos no implementada aún.")

    def _filter_results(self):
        """Permite filtrar los resultados del escaneo."""
        if not self.scan_results:
            messagebox.showwarning("Filtrar", "No hay resultados para filtrar.")
            return

        # Aquí iría la lógica para filtrar resultados
        messagebox.showinfo("Filtrar", "Filtrado de resultados no implementado aún.")

    def _sort_results(self):
        """Permite ordenar los resultados del escaneo."""
        if not self.scan_results:
            messagebox.showwarning("Ordenar", "No hay resultados para ordenar.")
            return

        # Aquí iría la lógica para ordenar resultados
        messagebox.showinfo("Ordenar", "Ordenamiento de resultados no implementado aún.")

    def _configure_security_analysis(self):
        """Configura las opciones del análisis de seguridad."""
        # Aquí iría la lógica para configurar el análisis de seguridad
        messagebox.showinfo("Análisis", "Configuración de análisis de seguridad no implementada aún.")

    def _view_vulnerabilities(self):
        """Muestra las vulnerabilidades detectadas en los dispositivos."""
        if not self.scan_results:
            messagebox.showwarning("Vulnerabilidades", "No hay resultados para mostrar vulnerabilidades.")
            return

        # Aquí iría la lógica para mostrar vulnerabilidades
        messagebox.showinfo("Vulnerabilidades", "Visualización de vulnerabilidades no implementada aún.")

    def _show_security_recommendations(self):
        """Muestra recomendaciones de seguridad para los dispositivos."""
        if not self.scan_results:
            messagebox.showwarning("Recomendaciones", "No hay resultados para mostrar recomendaciones.")
            return

        # Aquí iría la lógica para mostrar recomendaciones
        messagebox.showinfo("Recomendaciones", "Visualización de recomendaciones no implementada aún.")

    def _start_monitoring(self):
        """Inicia el monitoreo en tiempo real de la red."""
        # Aquí iría la lógica para iniciar el monitoreo
        messagebox.showinfo("Monitoreo", "Inicio de monitoreo no implementado aún.")

    def _stop_monitoring(self):
        """Detiene el monitoreo en tiempo real de la red."""
        # Aquí iría la lógica para detener el monitoreo
        messagebox.showinfo("Monitoreo", "Detención de monitoreo no implementado aún.")

    def _configure_monitoring(self):
        """Configura las opciones del monitoreo en tiempo real."""
        # Aquí iría la lógica para configurar el monitoreo
        messagebox.showinfo("Monitoreo", "Configuración de monitoreo no implementada aún.")

    def _view_alert_history(self):
        """Muestra el historial de alertas."""
        # Aquí iría la lógica para mostrar el historial de alertas
        messagebox.showinfo("Alertas", "Visualización de historial de alertas no implementada aún.")

    def _create_custom_alert_rule(self):
        """Crea una regla personalizada para alertas."""
        # Aquí iría la lógica para crear reglas de alertas
        messagebox.showinfo("Alertas", "Creación de reglas personalizadas no implementada aún.")

    def _manage_alert_rules(self):
        """Gestiona las reglas de alertas existentes."""
        # Aquí iría la lógica para gestionar reglas de alertas
        messagebox.showinfo("Alertas", "Gestión de reglas de alertas no implementada aún.")

    def _configure_notifications(self):
        """Configura las notificaciones del sistema."""
        # Aquí iría la lógica para configurar notificaciones
        messagebox.showinfo("Notificaciones", "Configuración de notificaciones no implementada aún.")

    def _configure_alerts(self):
        """Configura las alertas del sistema."""
        # Aquí iría la lógica para configurar alertas
        messagebox.showinfo("Alertas", "Configuración de alertas no implementada aún.")

    def _connect_ssh(self):
        """Establece una conexión SSH con un dispositivo seleccionado."""
        if not self.selected_device_ip:
            messagebox.showwarning("SSH", "No hay dispositivo seleccionado para conectar.")
            return

        # Aquí iría la lógica para conectar por SSH
        messagebox.showinfo("SSH", f"Conexión SSH a {self.selected_device_ip} no implementada aún.")

    def _connect_rdp(self):
        """Establece una conexión RDP con un dispositivo seleccionado."""
        if not self.selected_device_ip:
            messagebox.showwarning("RDP", "No hay dispositivo seleccionado para conectar.")
            return

        # Aquí iría la lógica para conectar por RDP
        messagebox.showinfo("RDP", f"Conexión RDP a {self.selected_device_ip} no implementada aún.")

    def _open_web_interface(self):
        """Abre la interfaz web de un dispositivo seleccionado."""
        if not self.selected_device_ip:
            messagebox.showwarning("Web", "No hay dispositivo seleccionado para abrir interfaz web.")
            return

        # Aquí iría la lógica para abrir la interfaz web
        messagebox.showinfo("Web", f"Apertura de interfaz web para {self.selected_device_ip} no implementada aún.")

    def _ping_device(self):
        """Realiza un ping a un dispositivo seleccionado."""
        if not self.selected_device_ip:
            messagebox.showwarning("Ping", "No hay dispositivo seleccionado para hacer ping.")
            return

        # Aquí iría la lógica para hacer ping
        messagebox.showinfo("Ping", f"Ping a {self.selected_device_ip} no implementado aún.")

    def _traceroute(self):
        """Realiza un traceroute a un dispositivo seleccionado."""
        if not self.selected_device_ip:
            messagebox.showwarning("Traceroute", "No hay dispositivo seleccionado para hacer traceroute.")
            return

        # Aquí iría la lógica para hacer traceroute
        messagebox.showinfo("Traceroute", f"Traceroute a {self.selected_device_ip} no implementado aún.")

    def _port_scan(self):
        """Realiza un escaneo de puertos a un dispositivo seleccionado."""
        if not self.selected_device_ip:
            messagebox.showwarning("Escaneo", "No hay dispositivo seleccionado para escanear puertos.")
            return

        # Aquí iría la lógica para escanear puertos
        messagebox.showinfo("Escaneo", f"Escaneo de puertos para {self.selected_device_ip} no implementado aún.")

    def _categorize_devices(self):
        """Permite categorizar los dispositivos del inventario."""
        if not self.scan_results:
            messagebox.showwarning("Categorizar", "No hay dispositivos para categorizar.")
            return

        # Aquí iría la lógica para categorizar dispositivos
        messagebox.showinfo("Categorizar", "Categorización de dispositivos no implementada aún.")

    def _add_device_manually(self):
        """Añade un dispositivo manualmente al inventario."""
        # Aquí iría la lógica para añadir dispositivos manualmente
        messagebox.showinfo("Añadir", "Adición manual de dispositivos no implementada aún.")

    def _edit_device(self):
        """Edita la información de un dispositivo seleccionado."""
        if not self.selected_device_ip:
            messagebox.showwarning("Editar", "No hay dispositivo seleccionado para editar.")
            return

        # Aquí iría la lógica para editar dispositivos
        messagebox.showinfo("Editar", f"Edición de dispositivo {self.selected_device_ip} no implementada aún.")

    def _import_inventory(self):
        """Importa un inventario desde un archivo."""
        # Aquí iría la lógica para importar inventario
        messagebox.showinfo("Importar", "Importación de inventario no implementada aún.")

    def _manage_database(self):
        """Gestiona la base de datos del inventario."""
        # Aquí iría la lógica para gestionar la base de datos
        messagebox.showinfo("Base de datos", "Gestión de base de datos no implementada aún.")

    def _show_quick_guide(self):
        """Muestra una guía rápida de uso de la aplicación."""
        from .help_functions import show_html_content
        show_html_content(self, "Guía Rápida", "quick_guide.html")

    def _show_tutorials(self):
        """Muestra tutoriales de uso de la aplicación."""
        from .help_functions import show_html_content
        show_html_content(self, "Tutoriales", "tutorials.html")

    def _show_faq(self):
        """Muestra preguntas frecuentes sobre la aplicación."""
        from .help_functions import show_html_content
        show_html_content(self, "Preguntas Frecuentes", "faq.html")

    def _reset_scan(self):
        """Reinicia la aplicación para un nuevo escaneo."""
        if self.scan_results and messagebox.askyesno("Nuevo escaneo",
                                                     "¿Desea iniciar un nuevo escaneo? Se perderán los resultados actuales si no han sido guardados."):
            self.scan_results = []
            self.filtered_results = []
            self._update_results_table()
            self.scan_status.set("Listo para escanear.")
        elif not self.scan_results:
            self.scan_status.set("Listo para escanear.")

    def _import_results(self):
        """Importa resultados de un archivo."""
        file_path = filedialog.askopenfilename(
            title="Importar resultados",
            filetypes=[("Archivos JSON", "*.json"), ("Todos los archivos", "*.*")]
        )
        if file_path:
            try:
                # Aquí iría la lógica para importar resultados
                messagebox.showinfo("Importar", "Importación de resultados no implementada aún.")
            except Exception as e:
                messagebox.showerror("Error", f"Error al importar resultados: {e}")

    def _export_results(self, format_type):
        """Exporta los resultados al formato especificado."""
        if not self.scan_results:
            messagebox.showwarning("Exportar", "No hay resultados para exportar.")
            return

        try:
            # CSV y JSON eliminados
            # if format_type == "csv": ...
            # elif format_type == "json": ...

            if format_type == "html":
                file_path = filedialog.asksaveasfilename(
                    title="Exportar a HTML",
                    defaultextension=".html",
                    filetypes=[("Archivos HTML", "*.html"), ("Todos los archivos", "*.*")])
                if file_path:
                    report_target = self.network_range.get()
                    html_exporter.HtmlExporter().save_report(self.scan_results, file_path, target=report_target)
                    messagebox.showinfo("Exportar", f"Resultados exportados correctamente a {file_path}")

            elif format_type == "pdf":
                file_path = filedialog.asksaveasfilename(
                    title="Exportar a PDF",
                    defaultextension=".pdf",
                    filetypes=[("Archivos PDF", "*.pdf"), ("Todos los archivos", "*.*")])
                if file_path:
                    # Aquí iría la lógica para exportar a PDF
                    messagebox.showinfo("Exportar", "Exportación a PDF no implementada aún.")

        except Exception as e:
            messagebox.showerror("Error", f"Error al exportar resultados: {e}")

    def _show_topology(self):
        """Muestra la topología de red interactiva."""
        if not self.scan_results:
            messagebox.showwarning("Topología", "No hay resultados de escaneo para mostrar la topología.")
            return

        try:
            # Crear la estructura de datos para la topología
            nodes = []
            edges = []
            node_id_map = {}
            
            # Añadir el router como nodo principal
            router_ip = self.network_range.get().split('/')[0]
            # Obtener la ruta base del directorio de recursos
            import os
            base_dir = os.path.join(os.path.dirname(__file__), 'resources', 'topologia', 'img')
            router_icon = os.path.join('file://', base_dir, 'Router.png').replace('\\', '/')
            
            nodes.append({
                'id': 1,
                'label': 'Router',
                'title': f'Router\nIP: {router_ip}',
                'shape': 'image',
                'image': router_icon,
                'size': 40
            })
            node_id_map[router_ip] = 1
            
            # Obtener la ruta base del directorio de recursos de imágenes
            import os
            img_dir = os.path.join(os.path.dirname(__file__), 'resources', 'topologia', 'img')
            
            # Añadir los dispositivos escaneados
            for i, device in enumerate(self.scan_results, 2):
                # Usar getattr para acceder de forma segura a los atributos
                ip = getattr(device, 'ip_address', f'unknown_ip_{i}')
                hostname = getattr(device, 'hostname', f'Dispositivo {i-1}')
                os_info = getattr(device, 'os', '')
                mac = getattr(device, 'mac_address', '')
                
                node_id_map[ip] = i
                
                # Determinar el tipo de dispositivo y la imagen correspondiente
                device_type = 'unknown'
                image_url = os.path.join('file://', img_dir, 'PC.png').replace('\\', '/')  # Dispositivo genérico
                
                # Determinar el tipo de dispositivo basado en la información disponible
                if os_info and 'windows' in str(os_info).lower():
                    device_type = 'windows'
                    image_url = os.path.join('file://', img_dir, 'Windows.png').replace('\\', '/')
                elif os_info and 'linux' in str(os_info).lower():
                    device_type = 'linux'
                    image_url = os.path.join('file://', img_dir, 'linux.png').replace('\\', '/')
                elif mac and any(mac.lower().startswith(prefix) for prefix in ['00:15:5d', '00:0c:29', '00:50:56']):
                    device_type = 'virtual'
                    image_url = os.path.join('file://', img_dir, 'virtual.png').replace('\\', '/')
                
                # Crear título con información del dispositivo
                title = f'IP: {ip}\n'
                if hostname and hostname != f'Dispositivo {i-1}':
                    title += f'Hostname: {hostname}\n'
                if os_info:
                    title += f'OS: {os_info}\n'
                if mac:
                    title += f'MAC: {mac}'
                
                nodes.append({
                    'id': i,
                    'label': hostname,
                    'title': title,
                    'shape': 'image',
                    'image': image_url,
                    'size': 35
                })
                
                # Conectar al router
                edges.append({
                    'from': 1,  # ID del router
                    'to': i,    # ID del dispositivo actual
                    'length': 150,
                    'color': '#7A99AC',
                    'width': 2
                })
            
            # Crear la estructura de datos final
            network_data = {
                'nodes': nodes,
                'edges': edges
            }
            
            # Convertir a JSON seguro para JavaScript
            import json
            network_json = json.dumps(network_data, ensure_ascii=False)
            
            # Obtener la ruta al archivo HTML
            import os
            html_file = os.path.join(os.path.dirname(__file__), 'resources', 'topologia', 'topology.html')
            
            # Mostrar la ventana con la topología
            self._show_network_topology(html_file, network_json)
            
        except Exception as e:
            logger.error(f"Error al generar la topología de red: {e}", exc_info=True)
            messagebox.showerror("Error", f"No se pudo generar la topología de red: {e}")
    
    def _show_network_topology(self, html_file, network_data):
        """Muestra la topología de red en una ventana WebEngine."""
        try:
            from PyQt5.QtWebEngineWidgets import QWebEngineView
            from PyQt5.QtCore import QUrl, Qt, QTimer
            from PyQt5.QtWidgets import QApplication, QMainWindow
            
            # Verificar si ya hay una instancia de QApplication
            app = QApplication.instance()
            if app is None:
                import sys
                app = QApplication(sys.argv)
                is_new_app = True
            else:
                is_new_app = False
            
            class TopologyViewer(QMainWindow):
                def __init__(self, html_file, network_data, parent=None):
                    super().__init__(parent, Qt.Window)
                    self.setWindowTitle("Topología de Red")
                    self.setGeometry(100, 100, 1000, 700)
                    self.setWindowModality(Qt.NonModal)  # No bloquear la ventana principal
                    
                    # Crear el visor web
                    self.browser = QWebEngineView()
                    self.setCentralWidget(self.browser)
                    
                    # Cargar el HTML en un temporizador para asegurar que la ventana ya esté mostrándose
                    QTimer.singleShot(100, lambda: self._load_html(html_file, network_data))
                
                def _load_html(self, html_file, network_data):
                    try:
                        # Cargar el HTML
                        with open(html_file, 'r', encoding='utf-8') as f:
                            html_content = f.read()
                        
                        # Inyectar los datos de la red en el HTML
                        html_content = html_content.replace(
                            '// INJECT_NETWORK_DATA_HERE',
                            f'var initialNetworkData = {network_data};\n        updateNetworkData(initialNetworkData);'
                        )
                        
                        # Cargar el HTML en el navegador
                        self.browser.setHtml(html_content, QUrl.fromLocalFile(html_file))
                    except Exception as e:
                        logger.error(f"Error al cargar la topología: {e}", exc_info=True)
                        self.browser.setHtml(f"""
                            <html><body>
                                <h2>Error al cargar la topología</h2>
                                <p>{str(e)}</p>
                            </body></html>
                        """)
            
            # Crear y mostrar la ventana
            self.topology_viewer = TopologyViewer(html_file, network_data, None)
            self.topology_viewer.show()
            
            # Si es una nueva aplicación, iniciar el bucle de eventos
            if is_new_app:
                app.exec_()
            
            return True
            
        except ImportError as e:
            logger.warning("PyQt5.QtWebEngine no está disponible. Mostrando datos en formato JSON.", exc_info=True)
            try:
                import json
                from tkinter import Tk, scrolledtext
                
                # Crear una ventana de Tkinter para mostrar los datos JSON
                root = Tk()
                root.title("Datos de Topología (Vista JSON)")
                
                text_area = scrolledtext.ScrolledText(root, wrap='word', width=80, height=30)
                text_area.pack(padx=10, pady=10, fill='both', expand=True)
                
                # Formatear el JSON con indentación
                formatted_json = json.dumps(json.loads(network_data), indent=2)
                text_area.insert('1.0', formatted_json)
                text_area.config(state='disabled')
                
                root.mainloop()
                return True
            except Exception as json_err:
                logger.error(f"Error al mostrar datos JSON: {json_err}", exc_info=True)
                messagebox.showerror("Error", "No se pudo mostrar la topología en formato JSON.")
                return False
                
        except Exception as e:
            logger.error(f"Error inesperado al mostrar la topología: {e}", exc_info=True)
            messagebox.showerror("Error", f"Error inesperado al mostrar la topología: {e}")
            return False

    def _show_statistics(self):
        """Muestra estadísticas de los dispositivos escaneados."""
        if not self.scan_results:
            messagebox.showwarning("Estadísticas", "No hay resultados para mostrar estadísticas.")
            return

        # Aquí iría la lógica para mostrar estadísticas
        messagebox.showinfo("Estadísticas", "Visualización de estadísticas no implementada aún.")

    def _show_change_history(self):
        """Muestra el historial de cambios en la red."""
        # Aquí iría la lógica para mostrar el historial de cambios
        messagebox.showinfo("Historial", "Visualización de historial no implementada aún.")

    def _refresh_view(self):
        """Refresca la vista actual."""
        self._update_results_table()

    def _run_security_analysis(self):
        """Ejecuta un análisis de seguridad en los dispositivos escaneados."""
        if not self.scan_results:
            messagebox.showwarning("Análisis", "No hay dispositivos para analizar.")
            return

        # Aquí iría la lógica para el análisis de seguridad
        messagebox.showinfo("Análisis", "Análisis de seguridad no implementado aún.")

    def _manage_credentials(self):
        """Gestiona las credenciales para acceso a dispositivos."""
        # Aquí iría la lógica para gestionar credenciales
        messagebox.showinfo("Credenciales", "Gestión de credenciales no implementada aún.")

    def _configure_scan_options(self):
        """Configura opciones avanzadas de escaneo."""
        # Aquí iría la lógica para configurar opciones de escaneo
        messagebox.showinfo("Opciones", "Configuración de opciones de escaneo no implementada aún.")

    def on_close(self):
        """Método que se ejecuta al cerrar la aplicación."""
        try:
            # Detener el servidor SQLite Web si está en ejecución
            if hasattr(self, 'sqlite_web_process') and self.sqlite_web_process:
                try:
                    logger.info("Cerrando el servidor SQLite Web...")
                    
                    # En Windows, usar taskkill para asegurar que se cierren todos los procesos hijos
                    if os.name == 'nt':
                        try:
                            # Obtener el ID del proceso
                            pid = self.sqlite_web_process.pid
                            # Usar taskkill para terminar el proceso y sus hijos
                            subprocess.run(
                                ['taskkill', '/F', '/T', '/PID', str(pid)],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                creationflags=subprocess.CREATE_NO_WINDOW
                            )
                            logger.info(f"Proceso SQLite Web (PID: {pid}) terminado con taskkill")
                        except Exception as taskkill_err:
                            logger.error(f"Error al usar taskkill: {taskkill_err}")
                            # Si falla taskkill, intentar con los métodos estándar
                            self.sqlite_web_process.terminate()
                    else:
                        # Para sistemas que no son Windows
                        self.sqlite_web_process.terminate()
                    
                    # Esperar un tiempo razonable para que el proceso termine (3 segundos)
                    try:
                        self.sqlite_web_process.wait(timeout=3)
                        logger.info("Servidor SQLite Web cerrado correctamente.")
                    except (subprocess.TimeoutExpired, AttributeError):
                        # Si no responde, forzar la terminación
                        logger.warning("El servidor SQLite Web no respondió, forzando cierre...")
                        try:
                            self.sqlite_web_process.kill()
                            self.sqlite_web_process.wait()
                            logger.info("Servidor SQLite Web forzado a cerrar.")
                        except Exception as kill_err:
                            logger.error(f"Error al forzar el cierre: {kill_err}")
                    except Exception as e:
                        logger.error(f"Error al esperar que termine el servidor SQLite Web: {e}")
                except Exception as e:
                    logger.error(f"Error al detener el servidor SQLite Web: {e}", exc_info=True)
                finally:
                    try:
                        # Asegurarse de que el proceso esté terminado
                        if self.sqlite_web_process and self.sqlite_web_process.poll() is None:
                            self.sqlite_web_process.kill()
                    except:
                        pass
                    self.sqlite_web_process = None
            
            # Cerrar la ventana principal
            super().destroy()
            
            # Salir de la aplicación
            self.quit()
            
        except Exception as e:
            logger.error(f"Error al cerrar la aplicación: {e}", exc_info=True)
            import os
            os._exit(1)  # Salida forzada en caso de error

    def _show_inventory(self):
        """Muestra el inventario completo de dispositivos usando SQLite Web."""
        try:
            # Ruta a la base de datos de inventario (en el directorio raíz del proyecto)
            project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
            db_path = os.path.join(project_root, 'network_inventory.db')
            db_path = os.path.abspath(db_path)
            
            # Verificar si la base de datos existe
            if not os.path.exists(db_path):
                error_msg = f"No se encontró la base de datos de inventario en:\n{db_path}"
                logger.error(error_msg)
                messagebox.showerror("Error", error_msg)
                return
            
            # Si ya hay un servidor en ejecución, solo abrir el navegador
            if hasattr(self, 'sqlite_web_process') and self.sqlite_web_process and self.sqlite_web_process.poll() is None:
                webbrowser.open('http://127.0.0.1:8080')
                return
            
            # Comando para iniciar el servidor SQLite Web usando el paquete instalado
            # Usamos la ruta completa al ejecutable de Python para asegurar que se use la instalación correcta
            python_exe = sys.executable
            cmd = [
                python_exe,
                '-m', 'sqlite_web',
                '--host', '127.0.0.1',  # Usar 127.0.0.1 en lugar de localhost para evitar problemas de resolución DNS
                '--port', '8080',
                '--no-browser',  # No abrir automáticamente el navegador
                '--read-only',    # Modo solo lectura
                db_path
            ]
            
            # Para depuración - mostrar el comando que se va a ejecutar
            logger.info(f"Python executable: {python_exe}")
            logger.info(f"Comando completo: {' '.join(cmd)}")
            
            logger.info(f"Iniciando servidor SQLite Web con base de datos: {db_path}")
            logger.info(f"Comando: {' '.join(cmd)}")
            
            # Configurar el comando como una cadena para usar con shell=True
            cmd_str = ' '.join(f'"{arg}"' if ' ' in arg else arg for arg in cmd)
            
            # Configuración específica para Windows
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
            
            # Iniciar el proceso con shell=True para manejar mejor la consola
            self.sqlite_web_process = subprocess.Popen(
                cmd_str,
                shell=True,
                cwd=project_root,  # Directorio raíz del proyecto
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW,
                startupinfo=startupinfo
            )
            
            # Esperar un momento para que el servidor se inicie
            time.sleep(2)
            
            # Verificar si el proceso sigue en ejecución
            if self.sqlite_web_process.poll() is not None:
                # El proceso terminó inesperadamente
                stdout, stderr = self.sqlite_web_process.communicate()
                error_details = stderr.decode('utf-8', errors='replace') if stderr else 'Sin detalles'
                error_msg = f"Error al iniciar el servidor SQLite Web.\nDetalles:\n{error_details}"
                logger.error(error_msg)
                messagebox.showerror("Error", error_msg)
                return
            
            # Esperar un poco más para asegurar que el servidor esté listo
            time.sleep(1)
            
            # Abrir el navegador
            webbrowser.open('http://127.0.0.1:8080')
            
            # Mostrar mensaje informativo
            messagebox.showinfo(
                "Visor de Inventario",
                "El visor de inventario se ha abierto en tu navegador.\n\n"
                "Puedes cerrar esta ventana cuando hayas terminado. El visor se cerrará automáticamente."
            )
            
        except Exception as e:
            error_msg = f"Error al iniciar el visor de inventario: {str(e)}"
            logger.error(error_msg, exc_info=True)
            messagebox.showerror("Error", error_msg)

    def _search_device(self):
        """Busca un dispositivo específico en el inventario."""
        # Aquí iría la lógica para buscar dispositivos
        messagebox.showinfo("Búsqueda", "Búsqueda de dispositivos no implementada aún.")

    def _manage_tags(self):
        """Gestiona las etiquetas para categorizar dispositivos."""
        # Aquí iría la lógica para gestionar etiquetas
        messagebox.showinfo("Etiquetas", "Gestión de etiquetas no implementada aún.")

    def _export_inventory(self):
        """Exporta el inventario completo."""
        # Aquí iría la lógica para exportar el inventario
        messagebox.showinfo("Exportar", "Exportación de inventario no implementada aún.")

    def _show_user_manual(self):
        """Muestra el manual de usuario."""
        from .help_functions import show_html_content
        show_html_content(self, "Manual de Usuario", "user_manual.html")

    def _show_about(self):
        """Muestra información sobre la aplicación."""
        from .help_functions import show_about_dialog
        show_about_dialog(self)

    def _check_updates(self):
        """Verifica si hay actualizaciones disponibles."""
        # Aquí iría la lógica para verificar actualizaciones
        messagebox.showinfo("Actualizaciones", "Verificación de actualizaciones no implementada aún.")

    def _report_issue(self):
        """Permite reportar un problema con la aplicación."""
        # Aquí iría la lógica para reportar problemas
        messagebox.showinfo("Reportar", "Reporte de problemas no implementado aún.")

    def _start_automatic_detailed_scans(self):
        """Inicia escaneos detallados automáticos (SNMP, SSH, WMI) para los dispositivos encontrados."""
        try:
            scan_types_to_run = []
            if self.snmp_detailed_scan_enabled.get(): scan_types_to_run.append("SNMP")
            if self.wmi_scan_enabled.get(): scan_types_to_run.append("WMI")
            if self.ssh_detailed_scan_enabled.get(): scan_types_to_run.append("SSH")

            if scan_types_to_run:
                status_msg = f"Iniciando escaneos detallados ({', '.join(scan_types_to_run)})..."
                self.after(0, lambda: self._update_scan_ui(True, status_msg))
            else: # No debería llegar aquí si la lógica en _perform_nmap_scan_thread es correcta
                self.after(0, lambda: self._update_scan_ui(False, "No hay escaneos detallados seleccionados."))
                return # No continuar si no hay nada que escanear detalladamente

            # Crear credenciales para los escaneos
            credentials = NetworkCredentials(
                username=self.ssh_username.get(),
                password=self.ssh_password.get(),
                domain=self.wmi_domain.get(),
                ssh_key_path=self.ssh_key_file.get(),
                snmp_community=self.snmp_community.get() # Use the value from the entry
            )

            # Contador para dispositivos escaneados con éxito
            successful_detailed_scans = 0
            total_devices = len(self.scan_results)

            # Use ThreadPoolExecutor for parallel detailed scans
            from concurrent.futures import ThreadPoolExecutor, as_completed
            max_detailed_workers = 3 # Limit parallel detailed scans to avoid overwhelming the network or target devices

            def perform_device_detailed_scan(device: Device):
                nonlocal successful_detailed_scans
                device_ip = device.ip_address
                logger.debug(f"[DEBUG] Evaluando escaneos detallados para {device_ip}")

                # Determine potential based on Nmap results (OS, open ports)
                # NmapScanner._parse_single_host already sets has_wmi_port, has_ssh_port, has_snmp_port
                # and determine_device_type sets has_wmi_potential based on type.
                # Let's rely on these flags.

                scan_success_for_this_device = False
                scan_types_attempted_for_this_device = []

                # Attempt WMI scan if enabled and potential exists
                if self.wmi_scan_enabled.get() and device.has_wmi_potential:
                    self.after(0, lambda ip=device_ip: self._update_scan_ui(
                        True, f"Escaneando {ip} con WMI..."))
                    logger.info(f"Intentando escaneo WMI para {device_ip}")
                    scan_types_attempted_for_this_device.append("WMI")
                    try:
                        wmi_success = self.wmi_scanner.scan_device(device, credentials)
                        if wmi_success:
                            scan_success = True
                            logger.info(f"Escaneo WMI exitoso para {device_ip}")
                        else:
                            logger.warning(f"Escaneo WMI fallido para {device_ip}")
                    except Exception as e:
                        logger.error(f"Error inesperado durante escaneo WMI para {device_ip}: {e}", exc_info=True)
                        device.wmi_specific_info = {"error": f"Error inesperado: {e}"} # Record the error

                # Attempt SSH scan if SSH toggle is enabled and potential exists
                if self.ssh_detailed_scan_enabled.get() and \
                   (device.has_ssh_port or any(x in device.get_os().lower() for x in ["linux", "unix", "mac", "os x"])):
                     if credentials.has_ssh_credentials():
                        self.after(0, lambda ip=device_ip: self._update_scan_ui(
                            True, f"Escaneando {ip} con SSH..."))
                        logger.info(f"Intentando escaneo SSH para {device_ip}")
                        scan_types_attempted_for_this_device.append("SSH")
                        try:
                            ssh_success = self.ssh_scanner.scan_device(device, credentials)
                            if ssh_success:
                                scan_success_for_this_device = True
                                logger.info(f"Escaneo SSH exitoso para {device_ip}")
                            else:
                                logger.warning(f"Escaneo SSH fallido para {device_ip}")
                        except Exception as e:
                            logger.error(f"Error inesperado durante escaneo SSH para {device_ip}: {e}", exc_info=True)
                            device.ssh_specific_info = {"error": f"Error inesperado: {e}"} # Record the error
                     else:
                        logger.info(f"Escaneo SSH para {device_ip} omitido: No se proporcionaron credenciales SSH.")
                        if not device.ssh_specific_info or "error" not in device.ssh_specific_info : # No sobrescribir un error existente
                            device.ssh_specific_info = {"info": "Omitido, sin credenciales SSH."}


                # Attempt SNMP scan if SNMP toggle is enabled and potential exists
                if self.snmp_detailed_scan_enabled.get() and \
                   (device.has_snmp_port or device.type == "Network Device"):
                     if credentials.snmp_community: # SNMP only needs community string
                        self.after(0, lambda ip=device_ip: self._update_scan_ui(
                            True, f"Escaneando {ip} con SNMP..."))
                        logger.info(f"Intentando escaneo SNMP para {device_ip}")
                        scan_types_attempted_for_this_device.append("SNMP")
                        try:
                            snmp_success = self.snmp_scanner.scan_device(device, credentials)
                            if snmp_success:
                                scan_success_for_this_device = True
                                logger.info(f"Escaneo SNMP exitoso para {device_ip}")
                            else:
                                logger.warning(f"Escaneo SNMP fallido para {device_ip}")
                        except Exception as e:
                            logger.error(f"Error inesperado durante escaneo SNMP para {device_ip}: {e}", exc_info=True)
                            device.snmp_info = {"error": f"Error inesperado: {e}"} # Record the error
                     else:
                        logger.info(f"Escaneo SNMP para {device_ip} omitido: No se proporcionó comunidad SNMP.")
                        if not device.snmp_info or "error" not in device.snmp_info: # No sobrescribir un error existente
                            device.snmp_info = {"info": "Omitido, sin comunidad SNMP."}


                if scan_success_for_this_device:
                    successful_detailed_scans += 1
                    logger.debug(f"Detalles actualizados para {device_ip} a través de {', '.join(scan_types_attempted_for_this_device)}")
                    # Update the UI for this specific device
                    self.after(0, lambda d=device: self._update_device_details_view(d))
                    # Update the main tree view to reflect potential changes (like OS from detailed scan)
                    self.after(0, self._populate_results_tree)
                elif scan_types_attempted_for_this_device:
                     logger.warning(f"Ningún escaneo detallado exitoso para {device_ip} (intentados: {', '.join(scan_types_attempted_for_this_device)})")
                     # Update the UI to show potential errors in detail view
                     self.after(0, lambda d=device: self._update_device_details_view(d))


            with ThreadPoolExecutor(max_workers=max_detailed_workers) as executor:
                futures = {executor.submit(perform_device_detailed_scan, device): device for device in self.scan_results}

                completed_detailed = 0
                for future in as_completed(futures):
                    device = futures[future]
                    completed_detailed += 1
                    # Update progress message
                    self.after(0, lambda c=completed_detailed, t=total_devices:
                              self.scan_status.set(f"Procesando escaneos detallados: {c}/{t} dispositivos."))

            final_status_msg = f"Escaneos detallados completados. {successful_detailed_scans}/{total_devices} dispositivos con detalles adicionales."
            if not scan_types_to_run: # Si por alguna razón se llamó sin toggles activos
                final_status_msg = "No se seleccionaron escaneos detallados."
                
            # Actualizar contadores y UI
            self._count_device_types()
            self.after(0, lambda: self._update_scan_ui(False, f"Escaneo detallado completado. {successful_detailed_scans}/{total_devices} dispositivos con detalles adicionales."))
            self.after(0, self._save_scan_to_db) # Save to DB after all scans are done

        except Exception as e:
            logger.error(f"Error en escaneos detallados automáticos: {e}", exc_info=True)
            self.after(0, lambda: self._update_scan_ui(False, "Error en escaneos detallados automáticos."))
            self.after(0, self._save_scan_to_db) # Attempt to save even on error

    def _update_results_table(self):
        """Actualiza la tabla de resultados."""
        # Limpiar la tabla
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Aplicar filtro si existe
        self._apply_filter()

if __name__ == '__main__':
    # Asegurarse que el directorio del proyecto está en sys.path para importaciones relativas
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # Reimportar módulos con el path actualizado (si es necesario para pruebas directas del GUI)
    from miproyectored.scanner.nmap_scanner import NmapScanner
    from miproyectored.scanner.wmi_scanner import WmiScanner
    from miproyectored.scanner.ssh_scanner import SshScanner
    from miproyectored.scanner.snmp_scanner import SnmpScanner
    from miproyectored.model.device import Device
    from miproyectored.risk.risk_analyzer import RiskAnalyzer
    from miproyectored.inventory.inventory_manager import InventoryManager
    from miproyectored.export import html_exporter # HtmlExporter es la clase
    from miproyectored.auth.network_credentials import NetworkCredentials

    app = NetworkScannerGUI()
    app.mainloop()
