"""
Módulo de funciones de ayuda para la interfaz gráfica usando PyQt5 WebEngine.
Requerimientos: pip install PyQt5 PyQtWebEngine
"""

import os
import logging
from PyQt5.QtWidgets import (QApplication, QMainWindow, QVBoxLayout,
                             QWidget, QMessageBox, QPushButton, QLabel,
                             QFrame, QHBoxLayout, QDialog)
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import QUrl, Qt
from PyQt5.QtGui import QColor
import sys

# Configurar logging
logger = logging.getLogger(__name__)


class HTMLViewer(QMainWindow):
    def __init__(self, parent=None, title="", html_file="", frameless=False):
        # Configuración de la ventana sin bordes si se solicita
        flags = Qt.Window | Qt.WindowStaysOnTopHint
        if frameless:
            flags |= Qt.FramelessWindowHint

        super().__init__(parent, flags)

        self.setWindowTitle(title)
        self.resize(1000, 800)

        # Configurar para que no cierre la aplicación al cerrar esta ventana
        self.setAttribute(Qt.WA_DeleteOnClose, False)

        # Configurar colores según el brandbook
        self.primary_dark = QColor(9, 31, 44)  # #091F2C
        self.primary_red = QColor(193, 0, 22)  # #C10016
        self.gray_medium = QColor(122, 153, 172)  # #7A99AC

        # Variables para el arrastre de la ventana
        self.dragging = False
        self.offset = None

        # Configurar estilo de la ventana
        if frameless:
            self.setStyleSheet("""
                QMainWindow {
                    background-color: #091F2C;
                    border: 2px solid #C10016;
                    border-radius: 5px;
                }
            """)

        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Layout principal
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)  # Eliminar márgenes
        main_layout.setSpacing(0)

        # Barra de título personalizada si es sin bordes
        if frameless:
            # Crear barra de título
            title_bar = QWidget()
            title_bar.setFixedHeight(30)
            title_bar.setStyleSheet("""
                QWidget {
                    background-color: #091F2C;
                    padding: 5px;
                }
            """)

            # Layout horizontal para la barra de título
            title_layout = QHBoxLayout(title_bar)
            title_layout.setContentsMargins(10, 0, 10, 0)

            # Título
            title_label = QLabel(title)
            title_label.setStyleSheet("""
                QLabel {
                    color: white;
                    font-weight: bold;
                    font-size: 12px;
                }
            """)

            # Botón de cerrar
            close_btn = QPushButton("×")
            close_btn.setFixedSize(20, 20)
            close_btn.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    color: white;
                    border: none;
                    font-size: 16px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    color: #C10016;
                }
            """)
            close_btn.clicked.connect(self.close)

            # Añadir widgets a la barra de título
            title_layout.addWidget(title_label)
            title_layout.addStretch()
            title_layout.addWidget(close_btn)

            # Añadir la barra de título al layout principal
            main_layout.addWidget(title_bar)

            # Conectar eventos para arrastrar la ventana
            title_bar.mousePressEvent = self.mousePressEvent
            title_bar.mouseMoveEvent = self.mouseMoveEvent

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

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and hasattr(self, 'offset') and self.offset is None:
            self.offset = event.globalPos() - self.pos()
            event.accept()
        elif event.button() == Qt.LeftButton and not hasattr(self, 'offset'):
            self.offset = event.globalPos() - self.pos()
            event.accept()

    def mouseMoveEvent(self, event):
        if hasattr(self, 'offset') and self.offset is not None and event.buttons() == Qt.LeftButton:
            self.move(event.globalPos() - self.offset)
            event.accept()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton and hasattr(self, 'offset'):
            self.offset = None
            event.accept()

    def closeEvent(self, event):
        # Aceptar el cierre de la ventana actual sin hacer nada más
        event.accept()
        # No llamar a quit() ni a sys.exit() aquí


def show_about_dialog(parent=None):
    """
    Muestra un diálogo simple 'Acerca de' con la información de la aplicación.
    """
    try:
        # Crear aplicación Qt si no existe
        app = QApplication.instance()
        if app is None:
            app = QApplication(sys.argv)
            is_new_app = True
        else:
            is_new_app = False

        # Crear ventana de diálogo sin padre para evitar conflictos con Tkinter
        dialog = QDialog(None, Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        dialog.setWindowTitle("Acerca de")
        dialog.setFixedSize(400, 400)

        # Configurar el ícono de la ventana
        try:
            icon_path = os.path.join(os.path.dirname(__file__), 'resources', 'SG - Logotipo IA negro.png')
            if os.path.exists(icon_path):
                from PyQt5.QtGui import QIcon, QPixmap
                from PyQt5.QtCore import QSize

                # Crear un ícono con tamaño adecuado
                icon = QIcon()
                pixmap = QPixmap(icon_path)

                # Asegurarse de que el ícono tenga un tamaño adecuado
                if not pixmap.isNull():
                    # Ajustar el tamaño si es muy grande
                    if pixmap.width() > 128 or pixmap.height() > 128:
                        pixmap = pixmap.scaled(128, 128, Qt.KeepAspectRatio, Qt.SmoothTransformation)

                    icon.addPixmap(pixmap)
                    dialog.setWindowIcon(icon)

                    # Configurar el ícono en la barra de título
                    dialog.setWindowFlags(dialog.windowFlags() | Qt.WindowSystemMenuHint | Qt.WindowMinMaxButtonsHint)

        except Exception as e:
            logger.warning(f"No se pudo cargar el ícono de la ventana: {e}")
            logger.exception("Detalles del error:")
        dialog.setStyleSheet("""
            QDialog {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 5px;
            }
            QLabel {
                color: #333;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }
            QPushButton {
                background-color: #C10016;
                color: white;
                border: none;
                padding: 8px 20px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #A00016;
            }
        """)

        # Layout principal
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(30, 30, 30, 20)
        layout.setSpacing(15)

        # Título
        title = QLabel("LÃBERIT")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #091F2C;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Subtítulo
        subtitle = QLabel("Herramienta de Inventariado y Monitoreo de Red")
        subtitle.setStyleSheet("font-size: 14px; font-weight: 600;")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        # Versión
        version = QLabel("Versión 3.0")
        version.setStyleSheet("color: #C10016; font-size: 12px;")
        version.setAlignment(Qt.AlignCenter)
        layout.addWidget(version)

        # Separador
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setStyleSheet("border: 1px solid #eee;")
        layout.addWidget(separator)

        # Descripción
        description = QLabel(
            "Esta aplicación permite escanear dispositivos en una red local, "
            "detectar sus servicios activos, analizar riesgos de seguridad "
            "y monitorear la red en tiempo real con nuestra tecnología propulsora."
        )
        description.setWordWrap(True)
        description.setStyleSheet("font-size: 12px; line-height: 1.4;")
        layout.addWidget(description)

        # Espaciador
        layout.addStretch()

        # Copyright
        copyright = QLabel("© 2025 LÃBERIT - Propulsando tus resultados")
        copyright.setStyleSheet("color: #7A99AC; font-size: 11px;")
        copyright.setAlignment(Qt.AlignCenter)
        layout.addWidget(copyright)

        # Botón de cerrar
        close_btn = QPushButton("Cerrar")
        close_btn.clicked.connect(dialog.accept)
        close_btn.setFixedWidth(100)

        # Contenedor para centrar el botón
        btn_container = QWidget()
        btn_layout = QHBoxLayout(btn_container)
        btn_layout.addStretch()
        btn_layout.addWidget(close_btn)
        btn_layout.addStretch()

        layout.addWidget(btn_container)

        # Mostrar el diálogo
        dialog.exec_()

        # Si creamos una aplicación, no la cerramos con sys.exit()
        # ya que podría cerrar el programa principal
        if is_new_app:
            # En lugar de sys.exit(), simplemente retornamos
            pass

    except Exception as e:
        logger.exception(f"Error al mostrar el diálogo Acerca de: {e}")
        if parent:
            from tkinter import messagebox
            messagebox.showerror("Error", f"No se pudo mostrar la información: {e}")


def show_html_content(parent, title: str, html_file: str, frameless=False):
    """
    Muestra un archivo HTML en una ventana con PyQt WebEngine.

    Args:
        parent: Widget padre (opcional)
        title: Título de la ventana
        html_file: Nombre del archivo HTML a mostrar (debe estar en resources/help/)
        frameless: Si es True, muestra la ventana sin bordes
    """
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
        viewer = HTMLViewer(None, title, file_path, frameless)

        # Centrar la ventana en la pantalla si es sin bordes
        if frameless:
            screen_geometry = QApplication.desktop().screenGeometry()
            x = (screen_geometry.width() - viewer.width()) // 2
            y = (screen_geometry.height() - viewer.height()) // 3  # Un poco más abajo del centro
            viewer.move(x, y)

        viewer.show()

        # Si creamos una nueva aplicación, ejecutar el bucle de eventos
        if is_new_app:
            # No usar sys.exit() para no cerrar la aplicación principal
            app.exec_()

    except Exception as e:
        logger.exception(f"Error al cargar contenido HTML: {e}")
        # Mostrar error en Tkinter si estamos integrando con una app existente
        if parent:
            from tkinter import messagebox
            messagebox.showerror("Error", f"No se pudo cargar el contenido:\n{e}")
