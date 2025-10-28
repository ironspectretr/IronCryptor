"""
IronCryptor GUI Application (PySide6)

This file contains the graphical user interface (GUI) for the IronCryptor application,
built using PySide6. It handles user interactions, theme management, and delegates
cryptographic operations to a separate worker thread/process for non-blocking execution.
It is designed to work in conjunction with 'cryptocore.py' (or similar core logic).
"""
import sys
import os
import struct
import zipfile
import shutil
import re
import io
import time
import multiprocessing
import concurrent.futures
import uuid

# Import the core cryptography logic from a separate module
from cryptocore import CryptoCore

# Cryptography primitives for key derivation and cipher operations
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# PySide6 (Qt for Python) imports for GUI components
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLineEdit, QLabel, QMessageBox, QGroupBox,
    QFrame, QComboBox, QProgressBar, QCheckBox, QRadioButton,
    QGraphicsOpacityEffect, QSpacerItem, QSizePolicy
)
from PySide6.QtGui import QIcon, QFont, QCursor, QPixmap, QDrag
from PySide6.QtCore import (
    Qt, Signal, QSize, QThread, QObject, QPoint, QTimer, QUrl, QMimeData,
    QPropertyAnimation, QEasingCurve, QCoreApplication
)


# --- Parallel Task Functions for Multiprocessing ---

def _encrypt_task(args):
    """
    Encrypts a single file or folder in a separate process.
    This function is executed by the ProcessPoolExecutor.
    """
    # Unpack arguments from the tuple, including the lock object
    path, password, output_dir, shred_original, lock = args
    core = CryptoCore(password, output_dir, shred_original)
    try:
        if os.path.isfile(path):
            # Pass the lock to the core method for synchronization if needed
            success, data = core._encrypt_file_gcm(path, shred_path=path, lock=lock)
        elif os.path.isdir(path):
            # Pass the lock to the core method for synchronization if needed
            success, data = core._encrypt_folder_gcm(folder_path=path, lock=lock)
        else:
            success, data = False, "Input path is neither a file nor a directory."

        if success:
            message, output_path = data
            return {'success': True, 'message': message, 'output_path': output_path, 'input_path': path}
        else:
            return {'success': False, 'message': data, 'input_path': path}
    except Exception as e:
        # Catch critical errors during parallel execution
        return {'success': False, 'message': f"Critical error in parallel process: {e}", 'input_path': path}


def _decrypt_task(args):
    """
    Decrypts a single file in a separate process.
    This function is executed by the ProcessPoolExecutor.
    """
    # Unpack arguments from the tuple, including the lock object
    path, password, output_dir, lock = args
    core = CryptoCore(password, output_dir)
    try:
        # Pass the lock to the core method for synchronization if needed
        success, data = core._decrypt_and_verify_gcm(input_path=path, lock=lock)
        if success:
            message, output_path = data
            return {'success': True, 'message': message, 'output_path': output_path, 'input_path': path}
        else:
            return {'success': False, 'message': data, 'input_path': path}
    except Exception as e:
        # Catch critical errors during parallel execution
        return {'success': False, 'message': f"Critical error in parallel process: {e}", 'input_path': path}


# --- GUI Background Worker ---
class CryptoWorker(QObject):
    """
    Worker class to run cryptographic operations in a separate QThread.
    It uses multiprocessing to handle the CPU-bound tasks.
    """
    # Signals for communication with the main GUI thread
    finished = Signal(bool, list)
    overall_progress = Signal(str)

    def __init__(self, mode, input_paths, password, output_dir=None, shred_original=False):
        super().__init__()
        self.mode = mode
        self.paths = input_paths
        self.password = password
        self.out_dir = output_dir
        self.shred = shred_original

    def run(self):
        """
        Main execution method for the worker. Sets up multiprocessing.
        """
        # Create a Manager and a Lock for process-safe synchronization
        manager = multiprocessing.Manager()
        lock = manager.Lock()

        # Determine the target function based on the operation mode
        target_func = _encrypt_task if self.mode == 'encrypt' else _decrypt_task

        # Prepare the list of tasks, including the lock object
        if self.mode == 'encrypt':
            tasks = [(p, self.password, self.out_dir, self.shred, lock) for p in self.paths]
        else:  # decrypt
            tasks = [(p, self.password, self.out_dir, lock) for p in self.paths]

        results = []
        try:
            # Use ProcessPoolExecutor for parallel execution of tasks
            with concurrent.futures.ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
                self.overall_progress.emit(f"Starting operation... Using {os.cpu_count()} cores.")
                # Map the target function to the list of tasks
                results = list(executor.map(target_func, tasks))
        except Exception as e:
            # Handle failure to start the parallel process
            results.append(
                {'success': False, 'message': f"Failed to start parallel process: {e}", 'input_path': 'Unknown'})

        # Emit the finished signal with the final results
        self.finished.emit(True, results)


# --- Theme Definitions and Styling ---

# Color palette for Dark Theme
DARK_THEME = {
    "background_main": "#202020",
    "background_secondary": "#2b2b2b",
    "background_titlebar": "#1e1e1e",
    "background_input": "#3c3c3c",
    "text_primary": "#ffffff",
    "text_secondary": "#b0b0b0",
    "text_title": "#0078d7",
    "border_color": "#505050",
    "button_hover": "#404040",
    "button_secondary_bg": "#3c3c3c",
}

# Color palette for Light Theme
LIGHT_THEME = {
    "background_main": "#f0f0f0",
    "background_secondary": "#ffffff",
    "background_titlebar": "#e1e1e1",
    "background_input": "#ffffff",
    "text_primary": "#000000",
    "text_secondary": "#5a5a5a",
    "text_title": "#0078d7",
    "border_color": "#cccccc",
    "button_hover": "#e6e6e6",
    "button_secondary_bg": "#f0f0f0",
}

# Dictionary mapping theme names to their color palettes
THEMES = {
    "Dark Theme": DARK_THEME,
    "Light Theme": LIGHT_THEME,
}

# QSS (Qt Style Sheet) template. Double curly braces are used to escape
# literal curly braces in the QSS, preventing them from being interpreted
# as format fields by Python's str.format().
THEME_QSS = """
/* General Window Style */
#CentralWidget {{
    background-color: {background_main};
    border-radius: 10px; /* Rounded corners for the entire window */
}}
QWidget {{
    font-family: Segoe UI;
    font-size: 10pt;
    color: {text_primary};
}}

/* Custom Title Bar */
#TitleBar {{
    background-color: {background_titlebar};
    border-top-left-radius: 10px;
    border-top-right-radius: 10px;
    height: 40px;
}}
#TitleLabel {{
    color: {text_title};
    font-weight: bold;
    font-size: 11pt;
    padding-left: 10px;
}}
#WindowTitle {{
    color: {text_secondary};
    font-size: 11pt;
    font-weight: bold;
}}

/* Title Bar Buttons */
#TitleBar QPushButton {{
    background-color: transparent;
    border: none;
    border-radius: 5px;
    width: 30px;
    height: 30px;
}}
#TitleBar QPushButton:hover {{
    background-color: {button_hover};
}}
#CloseButton:hover {{
    background-color: #E81123;
}}

/* Theme Selection ComboBox */
QComboBox {{
    border: 1px solid {border_color};
    border-radius: 4px;
    padding: 3px 8px;
    background-color: {background_input};
    color: {text_primary};
    min-width: 80px;
}}
QComboBox:hover {{
    border-color: #0078d7;
}}
QComboBox::drop-down {{
    border: none;
    background: transparent;
    width: 20px;
}}
QComboBox::down-arrow {{
    image: url(icons/down.ico);
    width: 12px;
    height: 12px;
}}
QComboBox QAbstractItemView {{
    background-color: {background_input};
    border: 1px solid {border_color};
    selection-background-color: #0078d7;
}}

/* Drag and Drop Area */
#DropFrame {{
    border: 3px dashed {border_color};
    border-radius: 15px;
    background-color: {background_secondary};
}}
#DropFrame:hover {{
    border-color: #0078d7;
}}
#DropLabel {{
    background-color: transparent;
    color: {text_secondary};
    font-size: 14pt;
    font-weight: normal;
}}
#DropLabel > b {{
    color: {text_primary};
}}

/* Password Input Field */
#PasswordField {{
    background-color: {background_input};
    border: 1px solid {border_color};
    border-top-left-radius: 5px;
    border-bottom-left-radius: 5px;
    padding-left: 10px;
    font-size: 11pt;
    min-width: 200px;
    max-width: 200px;
    min-height: 40px;
    max-height: 40px;
}}
#PasswordField:focus {{
    border: 1px solid #0078d7;
}}
#ShowPasswordButton {{
    background-color: {background_input};
    border: 1px solid {border_color};
    border-left: none;
    border-top-right-radius: 5px;
    border-bottom-right-radius: 5px;
    width: 40px;
    height: 40px;
}}
#ShowPasswordButton:pressed {{
    background-color: {button_hover};
}}

/* Main Operation Buttons */
#StartButton, #BackButton {{
    background-color: #0078d7;
    color: white;
    font-size: 12pt;
    font-weight: bold;
    padding: 12px;
    border-radius: 5px;
    border: none;
}}
#StartButton:hover, #BackButton:hover {{
    background-color: #008ae6;
}}
#StartButton:disabled {{
    background-color: #5a5a5a;
    color: #a0a0a0;
}}

/* Top Left Back Button Style */
#TopBackButton {{
    background-color: transparent;
    border: none;
    border-radius: 5px;
}}
#TopBackButton:hover {{
    background-color: {button_hover};
}}

/* Other Components */
#InfoLabel, #FileCountLabel {{
    font-size: 14pt;
    font-weight: bold;
    color: {text_primary};
}}
#FileCountLabel {{
    font-size: 11pt;
    font-weight: normal;
    color: {text_secondary};
}}

QCheckBox {{
    color: {text_secondary};
}}
QCheckBox::indicator {{
    width: 15px;
    height: 15px;
    border: 1px solid {border_color};
    border-radius: 3px;
}}
QCheckBox::indicator:checked {{
    background-color: #0078d7;
    border-color: #006cbf;
    image: url(icons/tick.ico);
}}

/* Result Icon */
#ResultIconLabel {{
    background-color: {background_secondary};
    border: 1px solid {border_color};
    border-radius: 10px;
}}

/* Message Boxes */
QMessageBox {{
    background-color: {background_main};
}}
QMessageBox QLabel#qt_msgbox_label {{
    color: {text_title};
    font-size: 11pt;
    font-weight: bold;
}}
QMessageBox QLabel#qt_msgbox_informativelabel {{
    color: {text_primary};
    font-size: 10pt;
}}
QMessageBox QPushButton {{
    padding: 6px 20px;
    font-size: 10pt;
    border-radius: 5px;
    min-width: 80px;
    background-color: {button_secondary_bg};
    border: 1px solid {border_color};
    color: {text_primary};
}}
QMessageBox QPushButton:hover {{
    background-color: {button_hover};
}}
"""

def apply_theme_style(theme_name):
    """Applies the selected theme's color palette to the QSS template."""
    theme = THEMES.get(theme_name, DARK_THEME)
    # The QSS string now uses double curly braces {{}} for literal braces,
    # and single curly braces {} for format fields, preventing the KeyError.
    return THEME_QSS.format(**theme)


# --- Custom Widgets ---

class StyledMessageBox:
    """A custom class to display themed QMessageBox instances."""
    @staticmethod
    def _show_message(parent, title, text, icon, buttons=QMessageBox.StandardButton.Ok):
        msg = QMessageBox(parent)
        msg.setWindowTitle(title)
        msg.setText(f"<b>{title}</b>")
        msg.setInformativeText(text)
        msg.setIcon(icon)
        msg.setStandardButtons(buttons)
        # Apply the current theme style to the message box
        msg.setStyleSheet(parent.styleSheet())
        return msg.exec()

    @staticmethod
    def show_info(parent, title, text):
        return StyledMessageBox._show_message(parent, title, text, QMessageBox.Icon.Information)

    @staticmethod
    def show_warning(parent, title, text):
        return StyledMessageBox._show_message(parent, title, text, QMessageBox.Icon.Warning)

    @staticmethod
    def show_critical(parent, title, text):
        return StyledMessageBox._show_message(parent, title, text, QMessageBox.Icon.Critical)

    @staticmethod
    def show_success(parent, title, text):
        # Using Information icon for success
        return StyledMessageBox._show_message(parent, title, text, QMessageBox.Icon.Information)

    @staticmethod
    def show_question(parent, title, text):
        return StyledMessageBox._show_message(parent, title, text, QMessageBox.Icon.Question,
                                              QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)


class DraggableResultLabel(QLabel):
    """
    A QLabel that displays the result icon and allows dragging the output files.
    """
    def __init__(self):
        super().__init__()
        self.setObjectName("ResultIconLabel")
        self.setFixedSize(150, 150)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setAcceptDrops(True)
        self.file_paths = []

    def set_file_paths(self, paths):
        """Sets the list of file paths to be dragged."""
        self.file_paths = paths

    def mousePressEvent(self, event):
        """Handles mouse press to initiate a drag operation."""
        if event.button() == Qt.MouseButton.LeftButton and self.file_paths:
            drag = QDrag(self)
            mime_data = QMimeData()
            urls = [QUrl.fromLocalFile(path) for path in self.file_paths]
            mime_data.setUrls(urls)
            drag.setMimeData(mime_data)
            # Start the drag operation
            drag.exec(Qt.DropAction.CopyAction | Qt.DropAction.MoveAction)
        super().mousePressEvent(event)


class AnimatedKeyIcon(QWidget):
    """
    A simple animated widget to show processing is underway.
    It animates the position and opacity of a key icon.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(100, 100)
        self.icon_label = QLabel(self)
        # Load the locked icon for animation
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icons", "locked.ico")
        pixmap = QPixmap(icon_path).scaled(96, 96, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        self.icon_label.setPixmap(pixmap)
        self.icon_label.setGeometry(0, 0, 100, 100)
        self.hide()

    def start_animation(self):
        """Starts the position and opacity animations."""
        self.show()

        # Calculate start and end Y positions relative to the parent widget
        start_y = self.parent().height() * 0.7
        end_y = self.parent().height() * 0.3
        x_pos = (self.parent().width() - self.width()) / 2

        self.move(int(x_pos), int(start_y))

        # Position animation (moving the icon up)
        self.pos_animation = QPropertyAnimation(self, b"pos")
        self.pos_animation.setDuration(2000)
        self.pos_animation.setStartValue(QPoint(int(x_pos), int(start_y)))
        self.pos_animation.setEndValue(QPoint(int(x_pos), int(end_y)))
        self.pos_animation.setEasingCurve(QEasingCurve.Type.OutCubic)

        # Opacity animation (fade in and fade out)
        opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(opacity_effect)
        self.opacity_animation = QPropertyAnimation(opacity_effect, b"opacity")
        self.opacity_animation.setDuration(2000)
        self.opacity_animation.setStartValue(0.0)
        self.opacity_animation.setKeyValueAt(0.5, 1.0)
        self.opacity_animation.setEndValue(0.0)

        # Hide the widget when the opacity animation finishes
        self.opacity_animation.finished.connect(self.hide)

        self.pos_animation.start()
        self.opacity_animation.start()


class IronCryptorWindow(QMainWindow):
    """
    The main application window for IronCryptor.
    Handles UI setup, page navigation, theme application, and operation initiation.
    """
    def __init__(self):
        super().__init__()
        self.setObjectName("MainWindow")
        self.setWindowTitle("Iron Cryptor")
        self.setFixedSize(520, 560)
        # Set window flags for a frameless, translucent window
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)

        # Determine the base path for resources (handles PyInstaller packaging)
        if getattr(sys, 'frozen', False):
            self.base_path = sys._MEIPASS
        else:
            self.base_path = os.path.dirname(os.path.abspath(__file__))

        self.setWindowIcon(QIcon(os.path.join(self.base_path, "icon.ico")))
        # Load icons used in the application
        self.icons = {
            "document": QPixmap(os.path.join(self.base_path, "icons", "document.ico")),
            "folder": QPixmap(os.path.join(self.base_path, "icons", "file.ico")),
            "locked": QPixmap(os.path.join(self.base_path, "icons", "locked.ico")),
            "unlocked": QPixmap(os.path.join(self.base_path, "icons", "unlocked.ico")),
        }
        self._setup_ui()
        self.apply_theme("Dark Theme")
        self._old_pos = None # Used for custom window dragging

    def _setup_ui(self):
        """Sets up the main structure of the UI."""
        self.central_widget = QWidget(self)
        self.central_widget.setObjectName("CentralWidget")
        self.setCentralWidget(self.central_widget)

        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        self._create_title_bar()
        self.main_layout.addWidget(self.title_bar)

        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(25, 20, 25, 25)
        self.main_layout.addWidget(self.content_widget, stretch=1)

        # Create and store different pages (main, encrypt, decrypt)
        self.pages = {
            'main': self._create_main_page(),
            'encrypt': self._create_operation_page('encrypt'),
            'decrypt': self._create_operation_page('decrypt'),
        }
        for page in self.pages.values():
            self.content_layout.addWidget(page)

        self.thread = None
        self.worker = None
        self.show_page('main')

    def _create_title_bar(self):
        """Creates the custom title bar with theme selection and window controls."""
        self.title_bar = QWidget()
        self.title_bar.setObjectName("TitleBar")
        title_layout = QHBoxLayout(self.title_bar)
        title_layout.setContentsMargins(10, 0, 5, 0)

        # Theme selection combo box
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Dark Theme", "Light Theme"])
        self.theme_combo.currentTextChanged.connect(self.apply_theme)
        title_layout.addWidget(self.theme_combo, alignment=Qt.AlignmentFlag.AlignLeft)

        # Window title label (displays current operation)
        self.window_title_label = QLabel("")
        self.window_title_label.setObjectName("WindowTitle")
        self.window_title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_layout.addStretch(1)
        title_layout.addWidget(self.window_title_label)
        title_layout.addStretch(2)

        # Minimize button
        btn_minimize = QPushButton(QIcon(os.path.join(self.base_path, "icons", "minimize.ico")), "")
        btn_minimize.clicked.connect(self.showMinimized)

        # Close button
        btn_close = QPushButton(QIcon(os.path.join(self.base_path, "icons", "close.ico")), "")
        btn_close.setObjectName("CloseButton")
        btn_close.clicked.connect(self.close)

        title_layout.addWidget(btn_minimize, alignment=Qt.AlignmentFlag.AlignRight)
        title_layout.addWidget(btn_close, alignment=Qt.AlignmentFlag.AlignRight)

    def _create_main_page(self):
        """Creates the main drag-and-drop page."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title_label = QLabel("Iron Cryptor")
        title_label.setObjectName("TitleLabel")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        subtitle_label = QLabel("User Interface Update")
        subtitle_label.setObjectName("SubTitleLabel")
        subtitle_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Drag and drop frame
        drop_frame = QFrame()
        drop_frame.setObjectName("DropFrame")
        drop_frame.setAcceptDrops(True)
        drop_layout = QVBoxLayout(drop_frame)
        drop_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        drop_label = QLabel("Drag files or folders here\nor\nclick to select")
        drop_label.setObjectName("DropLabel")
        drop_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        drop_label.setWordWrap(True)
        drop_layout.addWidget(drop_label)

        def file_dropped(event):
            """Processes dropped files/folders."""
            if event.mimeData().hasUrls():
                self.process_input_paths([url.toLocalFile() for url in event.mimeData().urls()])

        def select_files():
            """Opens a file dialog to select files."""
            # Use getOpenFileNames to allow selecting multiple files
            paths, _ = QFileDialog.getOpenFileNames(self, "Select File or Folder")
            if paths: self.process_input_paths(paths)

        # Connect drag-and-drop and click events
        drop_frame.dragEnterEvent = lambda e: e.mimeData().hasUrls() and e.acceptProposedAction()
        drop_frame.dropEvent = file_dropped
        drop_frame.mousePressEvent = lambda e: select_files()

        layout.addStretch(1)
        layout.addWidget(title_label)
        layout.addWidget(subtitle_label)
        layout.addSpacing(20)
        layout.addWidget(drop_frame, stretch=8)
        layout.addStretch(1)
        return page

    def _create_operation_page(self, mode):
        """Creates the encryption or decryption operation page."""
        page = QWidget()
        page.setObjectName(f"{mode.capitalize()}Page")
        layout = QVBoxLayout(page)

        # Header with back button and info label
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)

        # Back button to main menu
        btn_back_main = QPushButton(QIcon(os.path.join(self.base_path, "icons", "btmain.ico")), "")
        btn_back_main.setObjectName("TopBackButton")
        btn_back_main.setFixedSize(40, 40)
        btn_back_main.setIconSize(QSize(24, 24))
        btn_back_main.clicked.connect(self.go_to_main_menu)
        page.btn_back_main = btn_back_main

        info_label = QLabel("Encryption" if mode == 'encrypt' else "Decryption")
        info_label.setObjectName("InfoLabel")
        info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        page.info_label = info_label

        # Spacer to balance the layout
        right_spacer = QWidget()
        right_spacer.setFixedSize(40, 40)

        header_layout.addWidget(btn_back_main)
        header_layout.addWidget(info_label, 1)
        header_layout.addWidget(right_spacer)
        layout.addLayout(header_layout)
        layout.addSpacing(15)

        # Content stack for icons, animation, and result
        content_stack = QWidget()
        stack_layout = QVBoxLayout(content_stack)
        stack_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Icon container for selected files/folders
        icon_container = QWidget()
        page.icon_container_layout = QHBoxLayout(icon_container)
        page.icon_container_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        page.icon_container_layout.setSpacing(20)
        stack_layout.addWidget(icon_container)

        # Label to show the count of selected files
        file_count_label = QLabel("")
        file_count_label.setObjectName("FileCountLabel")
        file_count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        page.file_count_label = file_count_label
        stack_layout.addWidget(file_count_label)

        # Animation and result widgets
        page.key_animation = AnimatedKeyIcon(content_stack)
        page.result_icon_label = DraggableResultLabel()
        page.result_icon_label.hide()
        stack_layout.addWidget(page.result_icon_label)

        layout.addWidget(content_stack, stretch=1)

        # Password input section
        password_input_container = QWidget()
        page.pass_widget = password_input_container
        password_layout = QHBoxLayout(password_input_container)
        password_layout.setSpacing(0)
        password_layout.addStretch(1)

        txt_password = QLineEdit()
        txt_password.setObjectName("PasswordField")
        txt_password.setPlaceholderText("Enter password...")
        txt_password.setEchoMode(QLineEdit.EchoMode.Password)
        page.txt_password = txt_password

        # Show/Hide password button
        btn_show_pass = QPushButton(QIcon(os.path.join(self.base_path, "icons", "eye-closed.ico")), "")
        btn_show_pass.setObjectName("ShowPasswordButton")

        def show_password():
            txt_password.setEchoMode(QLineEdit.EchoMode.Normal)
            btn_show_pass.setIcon(QIcon(os.path.join(self.base_path, "icons", "eye.ico")))

        def hide_password():
            txt_password.setEchoMode(QLineEdit.EchoMode.Password)
            btn_show_pass.setIcon(QIcon(os.path.join(self.base_path, "icons", "eye-closed.ico")))

        btn_show_pass.pressed.connect(show_password)
        btn_show_pass.released.connect(hide_password)

        password_layout.addWidget(txt_password)
        password_layout.addWidget(btn_show_pass)
        password_layout.addStretch(1)
        layout.addWidget(password_input_container)

        # Encryption-specific options
        if mode == 'encrypt':
            chk_shred_file = QCheckBox("Securely shred originals")
            page.chk_shred_file = chk_shred_file
            layout.addWidget(chk_shred_file, alignment=Qt.AlignmentFlag.AlignCenter)

        layout.addSpacing(15)

        # Progress label
        page.progress_label = QLabel("")
        page.progress_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        page.progress_label.hide()
        layout.addWidget(page.progress_label)

        # Start operation button
        btn_start = QPushButton("Encrypt" if mode == 'encrypt' else "Decrypt")
        btn_start.setObjectName("StartButton")
        btn_start.clicked.connect(lambda: self.start_operation(mode))
        page.btn_start = btn_start
        layout.addWidget(btn_start)

        # Back to main menu button (shown after operation is complete)
        btn_back = QPushButton("Back to Main Menu")
        btn_back.setObjectName("BackButton")
        btn_back.clicked.connect(self.go_to_main_menu)
        page.btn_back = btn_back
        page.btn_back.hide()
        layout.addWidget(btn_back)

        page.input_paths = []
        return page

    def show_page(self, page_name):
        """Switches the visible page in the content area."""
        for name, page in self.pages.items():
            page.setVisible(name == page_name)
        self.current_page = page_name
        # Update the window title based on the current page
        self.window_title_label.setText("" if page_name == 'main' else "Iron Cryptor")

    def apply_theme(self, theme_name):
        """Applies the selected theme's QSS stylesheet."""
        self.setStyleSheet(apply_theme_style(theme_name))
        # Re-apply the style to the combo box itself to prevent it from inheriting the main window style
        self.theme_combo.setStyleSheet(self.theme_combo.styleSheet())

    def process_input_paths(self, paths):
        """
        Analyzes the selected paths to determine the operation mode (encrypt/decrypt).
        """
        if not paths: return

        # Check if all selected files are encrypted (.ironcrypt)
        is_all_ironcrypt = all(p.lower().endswith('.ironcrypt') for p in paths)
        is_any_ironcrypt = any(p.lower().endswith('.ironcrypt') for p in paths)

        # Prevent mixing encrypted and unencrypted files
        if is_any_ironcrypt and not is_all_ironcrypt:
            StyledMessageBox.show_warning(self, "Invalid Selection",
                                          "Cannot process encrypted and normal files simultaneously.")
            return

        # Determine mode: decrypt if all are .ironcrypt, otherwise encrypt
        mode = 'decrypt' if is_all_ironcrypt else 'encrypt'
        page = self.pages[mode]

        self.reset_operation_page(mode)
        page.input_paths = paths
        self.update_operation_page_display(mode, paths)
        self.show_page(mode)

    def update_operation_page_display(self, mode, paths):
        """Updates the icons and file count label on the operation page."""
        page = self.pages[mode]
        layout = page.icon_container_layout

        # Clear existing icons
        while layout.count():
            child = layout.takeAt(0)
            if child.widget(): child.widget().deleteLater()

        if mode == 'encrypt':
            files = [p for p in paths if os.path.isfile(p)]
            folders = [p for p in paths if os.path.isdir(p)]

            # Show document icon if files are selected
            if files:
                icon_label = QLabel()
                icon_label.setPixmap(self.icons["document"].scaled(96, 96, Qt.AspectRatioMode.KeepAspectRatio,
                                                                   Qt.TransformationMode.SmoothTransformation))
                layout.addWidget(icon_label)

            # Show folder icon if folders are selected
            if folders:
                icon_label = QLabel()
                icon_label.setPixmap(self.icons["folder"].scaled(96, 96, Qt.AspectRatioMode.KeepAspectRatio,
                                                                 Qt.TransformationMode.SmoothTransformation))
                layout.addWidget(icon_label)

            # Update file count label
            text_parts = []
            if files: text_parts.append(f"{len(files)} file(s)")
            if folders: text_parts.append(f"{len(folders)} folder(s)")
            page.file_count_label.setText(" and ".join(text_parts) + " selected.")

        elif mode == 'decrypt':
            # Show locked icon for decryption
            icon_label = QLabel()
            icon_label.setPixmap(self.icons["locked"].scaled(128, 128, Qt.AspectRatioMode.KeepAspectRatio,
                                                             Qt.TransformationMode.SmoothTransformation))
            layout.addWidget(icon_label)
            page.file_count_label.setText(f"{len(paths)} encrypted file(s) selected.")

    def start_operation(self, mode):
        """Initiates the cryptographic operation in a separate thread."""
        page = self.pages[mode]
        password = page.txt_password.text()

        if not page.input_paths:
            StyledMessageBox.show_warning(self, "Missing Input", "Please select file(s) first.")
            return
        if not password:
            StyledMessageBox.show_warning(self, "Missing Password", "Please enter your password.")
            return

        shred = False
        if mode == 'encrypt' and page.chk_shred_file.isChecked():
            # Confirmation for secure shredding
            reply = StyledMessageBox.show_question(self, 'Secure Shredding Confirmation',
                                                   'Original file(s)/folder(s) will be permanently deleted. This action is irreversible!<br><br>Do you want to continue?')
            if reply != QMessageBox.StandardButton.Yes: return
            shred = True

        self.set_ui_for_processing(mode, True)

        # Use a temporary directory for output before user saves
        temp_dir = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp", "IronCryptor")
        os.makedirs(temp_dir, exist_ok=True)

        # Setup and start the worker thread
        self.thread = QThread()
        self.worker = CryptoWorker(mode, page.input_paths, password, temp_dir, shred)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_operation_finished)
        self.worker.overall_progress.connect(lambda msg: page.progress_label.setText(msg))
        self.thread.start()

    def set_ui_for_processing(self, mode, is_processing):
        """Updates the UI state during processing."""
        page = self.pages[mode]
        page.btn_start.setVisible(not is_processing)
        page.pass_widget.setVisible(not is_processing)
        page.progress_label.setVisible(is_processing)
        if mode == 'encrypt': page.chk_shred_file.setVisible(not is_processing)
        if is_processing: page.key_animation.start_animation()

    def on_operation_finished(self, success, results):
        """Handles the completion of the worker thread."""
        # Clean up thread resources
        self.thread.quit()
        self.thread.wait()

        mode = self.current_page
        page = self.pages[mode]

        # Stop and hide processing indicators
        page.key_animation.hide()
        page.progress_label.hide()

        # Separate successful and failed operations
        successful_paths = [res['output_path'] for res in results if res.get('success')]
        failed_ops = [res for res in results if not res.get('success')]

        # Display errors if any operations failed
        if failed_ops:
            error_details = [
                f"<li><b>{os.path.basename(fail.get('input_path', 'Unknown'))}:</b> {fail['message']}</li>" for fail
                in failed_ops]
            StyledMessageBox.show_critical(self, f"{len(failed_ops)} Operation(s) Failed",
                                           f"The following errors occurred:<ul>{''.join(error_details)}</ul>")

        # If no successful operations, reset the page and return
        if not successful_paths:
            self.reset_operation_page(mode)
            return

        # Update UI for successful completion
        for i in range(page.icon_container_layout.count()):
            page.icon_container_layout.itemAt(i).widget().hide()
        page.file_count_label.setText(f"{len(successful_paths)} operation(s) completed successfully.")

        # Hide input controls
        page.pass_widget.hide()
        page.btn_start.hide()
        if mode == 'encrypt': page.chk_shred_file.hide()
        page.btn_back_main.hide()

        # Show the draggable result icon
        result_icon = self.icons["locked"] if mode == 'encrypt' else self.icons["unlocked"]
        page.result_icon_label.setPixmap(result_icon.scaled(128, 128, Qt.AspectRatioMode.KeepAspectRatio,
                                                             Qt.TransformationMode.SmoothTransformation))
        page.result_icon_label.set_file_paths(successful_paths)
        # Connect click to a save function (alternative to drag-and-drop)
        page.result_icon_label.clicked.connect(lambda: self.save_result_files(successful_paths))
        page.result_icon_label.show()
        page.btn_back.show()

    def save_result_files(self, source_paths):
        """Opens a dialog to select a directory and copies the output files there."""
        save_dir = QFileDialog.getExistingDirectory(self, "Select Save Directory")
        if save_dir:
            try:
                for source_path in source_paths:
                    # Clean up the filename (remove the random code added during processing)
                    base_name = os.path.basename(source_path)
                    cleaned_name = re.sub(r'_\d+$', '', base_name)
                    dest_path = os.path.join(save_dir, cleaned_name)

                    # Handle file or directory copy
                    if os.path.isdir(source_path):
                        if os.path.exists(dest_path): shutil.rmtree(dest_path)
                        shutil.copytree(source_path, dest_path)
                    else:
                        shutil.copy2(source_path, dest_path)

                StyledMessageBox.show_success(self, "Saved Successfully",
                                              f"Files were successfully saved to '{save_dir}'.")
            except Exception as e:
                StyledMessageBox.show_critical(self, "Error", f"An error occurred while saving files: {e}")

    def reset_operation_page(self, mode):
        """Resets the operation page to its initial state."""
        page = self.pages[mode]
        page.input_paths = []
        page.txt_password.clear()
        page.btn_start.show()
        page.pass_widget.show()
        page.progress_label.hide()
        page.btn_back.hide()
        page.btn_back_main.show()
        page.result_icon_label.hide()
        page.file_count_label.clear()

        if mode == 'encrypt':
            page.chk_shred_file.setChecked(False)
            page.chk_shred_file.show()

        # Clear icons
        layout = page.icon_container_layout
        while layout.count():
            child = layout.takeAt(0)
            if child.widget(): child.widget().deleteLater()

    def go_to_main_menu(self):
        """Navigates back to the main page."""
        self.show_page('main')

    # --- Custom Window Dragging Functions ---

    def mousePressEvent(self, event):
        """Stores the initial position for dragging the frameless window."""
        if event.button() == Qt.MouseButton.LeftButton:
            # globalPosition() is the PySide6 equivalent of PyQt5's globalPos()
            self._old_pos = event.globalPosition().toPoint()
            event.accept()

    def mouseMoveEvent(self, event):
        """Moves the window based on mouse movement."""
        if event.buttons() == Qt.MouseButton.LeftButton and self._old_pos:
            # Calculate the delta movement
            delta = event.globalPosition().toPoint() - self._old_pos
            # Move the window
            self.move(self.pos() + delta)
            # Update the old position
            self._old_pos = event.globalPosition().toPoint()
            event.accept()

    def mouseReleaseEvent(self, event):
        """Clears the old position on mouse release."""
        self._old_pos = None
        event.accept()


if __name__ == '__main__':
    # PySide6 application setup best practices
    # Disable high DPI scaling if necessary for consistent UI size
    os.environ["QT_ENABLE_HIGHDPI_SCALING"] = "0"
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"

    # Check if an application instance already exists
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)

    app.setApplicationName("Iron Cryptor")

    window = IronCryptorWindow()
    window.show()
    # Use app.exec() for PySide6 event loop
    sys.exit(app.exec())
