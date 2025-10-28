# IronCryptor

An advanced file cryptor project.

---

## 🚀 Overview

IronCryptor is a robust and easy-to-use file encryption utility designed to protect your sensitive data with modern cryptographic standards. Built primarily with Python and PySide6, it offers a cross-platform graphical interface that simplifies the process of securing files and folders.

## ✨ Features

The project is structured to provide both a command-line interface (CLI) and a powerful Graphical User Interface (GUI).

### Core Features
*   **Strong Encryption:** Utilizes industry-standard, modern encryption algorithms (e.g., AES-256 GCM via the `cryptography` library).
*   **Parallel Processing:** Leverages multi-processing to handle multiple encryption/decryption tasks concurrently, significantly speeding up batch operations.
*   **Secure Shredding:** An optional feature to securely overwrite and delete original files after successful encryption, preventing data recovery.
*   **Cross-Platform GUI:** A sleek, modern interface built with PySide6, ensuring a consistent look and feel across Windows, macOS, and Linux.

### GUI Specifics
*   **Drag-and-Drop Support:** Easily initiate encryption or decryption by dragging files and folders onto the application window.
*   **Theming:** Supports both Light and Dark themes for a comfortable user experience.
*   **Result Handling:** Allows users to easily save or drag the resulting encrypted/decrypted files from a dedicated result icon.

---

## 🛠️ Installation and Usage

### Prerequisites
*   Python 3.x
*   The required Python libraries (`PySide6`, `cryptography`, etc.)

### Setup
1.  Clone the repository:
    ```bash
    git clone https://github.com/ironspectretr/IronCryptor.git
    cd IronCryptor
    ```
2.  Install dependencies (assuming a `requirements.txt` file exists):
    ```bash
    pip install -r requirements.txt
    ```

### Running the GUI
```bash
python ironcryptor_guiSide6.py
# If you renamed the file:
# python arayuz.py
```

### Running the CLI
```bash
python icryptor_cli.py
```

---

## 🎯 Future Goals (To be filled by the developer)

This section outlines the planned features and long-term vision for the IronCryptor project. Please fill the placeholders below with your specific development goals.

*   İ18 language update.
*   Own designed icon and UI icons.
*   Keyfile logs.

---

## 📄 License

This project is licensed under the MIT License - see the `LICENSE` file for details.
