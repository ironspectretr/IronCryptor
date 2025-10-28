# IronCryptor

An simple file cryptor project.

---

## 🚀 Overview

IronCryptor is a robust and easy-to-use file encryption utility designed to protect your sensitive data with modern cryptographic standards. Built primarily with Python and PySide6, it offers a cross-platform graphical interface that simplifies the process of securing files and folders.

## ✨ Features

The project is structured to provide both a command-line interface (CLI) and a powerful Graphical User Interface (GUI).

### Core Features
*   **Strong Encryption:** Utilizes industry-standard, modern encryption algorithms (e.g., AES-256 GCM via the `cryptography` library).
*   **Parallel Processing:** Leverages multi-processing to handle multiple encryption/decryption tasks concurrently, significantly speeding up batch operations.
*   **Secure Shredding:** An optional feature to securely overwrite and delete original files after successful encryption, preventing data recovery.
*   **Command-Line Interface (CLI):** A powerful, scriptable interface for automation and batch processing, ideal for server environments or advanced users.
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

### CLI Usage Details

The command-line interface provides a quick and powerful way to encrypt and decrypt files or folders directly from your terminal.

#### General Syntax

```bash
python icryptor_cli.py [-h] (-e PATH | -d PATH) [-p PASSWORD] [-o OUTPUT_DIR] [--shred]
```

#### Arguments

| Argument | Description | Required | Example |
| :--- | :--- | :--- | :--- |
| `-e PATH`, `--encrypt PATH` | Path to the file or folder you want to **encrypt**. | Mutually Exclusive | `-e my_secret_file.txt` |
| `-d PATH`, `--decrypt PATH` | Path to the `.ironcrypt` file you want to **decrypt**. | Mutually Exclusive | `-d my_secret_file.txt.ironcrypt` |
| `-p PASSWORD`, `--password PASSWORD` | The password for the operation. **(Security Warning: It is recommended to omit this and enter the password when prompted for better security.)** | Optional | `-p MyStrongP@ssword123` |
| `-o OUTPUT_DIR`, `--output OUTPUT_DIR` | The directory where the resulting encrypted or decrypted file will be saved. (Default: current directory `.`) | Optional | `-o /path/to/output/folder` |
| `--shred` | Securely overwrite and delete the original file/folder after successful encryption. **USE WITH EXTREME CAUTION!** | Optional | `--shred` |

#### Examples

**1. Encrypting a file with a secure prompt:**

```bash
python icryptor_cli.py -e important_document.pdf
# You will be prompted to enter the password securely.
```

**2. Decrypting a file and saving it to a specific folder:**

```bash
python icryptor_cli.py -d important_document.pdf.ironcrypt -o ./decrypted_files
```

**3. Encrypting a folder and securely shredding the original:**

```bash
python icryptor_cli.py -e my_secret_folder --shred
# The original 'my_secret_folder' will be securely deleted after encryption.
```
