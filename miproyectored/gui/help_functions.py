"""
Módulo de funciones de ayuda para la interfaz gráfica usando PyQt5 WebEngine.
Requerimientos: pip install PyQt5 PyQtWebEngine
"""

import os
import logging
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout,
                             QWidget, QMessageBox, QPushButton, QLabel,
                             QFrame, QHBoxLayout)
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import QUrl, Qt
from PyQt5.QtGui import QFont, QPalette, QColor
import sys

# Configurar logging
logger = logging.getLogger(__name__)

class HTMLViewer(QMainWindow):
    def __init__(self, parent=None, title="", html_file=""):
        super().__init__(parent, Qt.Window)  # Qt.Window hace que sea una ventana independiente
        self.setWindowTitle(title)
        self.resize(1000, 800)

        # Configurar para que no cierre la aplicación al cerrar esta ventana
        self.setAttribute(Qt.WA_DeleteOnClose, False)

        # Configurar colores según el brandbook
        self.primary_dark = QColor(9, 31, 44)    # #091F2C
        self.primary_red = QColor(193, 0, 22)    # #C10016
        self.gray_medium = QColor(122, 153, 172) # #7A99AC

        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Layout principal
        main_layout = QVBoxLayout(central_widget)  # Pasar el widget padre al layout
        main_layout.setContentsMargins(0, 0, 0, 0)  # Eliminar márgenes

        # Visor web
        self.web_view = QWebEngineView()
        main_layout.addWidget(self.web_view)

        try:
            file_path = os.path.abspath(html_file)
            file_url = QUrl.fromLocalFile(file_path)
            self.web_view.load(file_url)
        except Exception as e:
            logger.error(f"Error loading HTML: {e}")
            QMessageBox.critical(self, "Error", f"No se pudo cargar el archivo:\n{e}")

    def closeEvent(self, event):
        # Sobrescribir el evento de cierre para evitar que cierre la aplicación
        event.accept()  # Aceptar el cierre de la ventana actual





def show_html_content(parent, title: str, html_file: str):
    """Muestra un archivo HTML en una ventana con PyQt WebEngine."""
    try:
        # Ruta del archivo HTML
        file_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'gui',
            'resources',
            'help',
            html_file
        )

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Archivo no encontrado: {file_path}")

        # Crear aplicación Qt si no existe
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
            app.setStyle('Fusion')
            is_new_app = True
        else:
            is_new_app = False

        # Crear y mostrar ventana
        viewer = HTMLViewer(None, title, file_path)  # Always create as top-level window
        viewer.show()

        # Ejecutar el loop de Qt solo si creamos una nueva aplicación
        if is_new_app:
            sys.exit(app.exec_())

    except Exception as e:
        logger.exception(f"Error al cargar contenido HTML: {e}")
        # Mostrar error en Tkinter si estamos integrando con una app existente
        if parent:
            from tkinter import messagebox
            messagebox.showerror("Error", f"No se pudo cargar el contenido:\n{e}")
