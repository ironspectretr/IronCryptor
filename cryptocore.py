import os
import struct
import zipfile
import shutil
import time
import uuid

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# --- Constants ---
MAGIC_NUMBER = b'IRONCRYPT'  # Used to identify encrypted files.
FILE_FORMAT_VERSION = 6      # Version of the file structure.
SALT_SIZE = 16               # Size of the salt for key derivation in bytes.
NONCE_SIZE = 12              # Size of the nonce for AES-GCM in bytes.
TAG_SIZE = 16                # Size of the authentication tag for AES-GCM in bytes.
KEY_SIZE = 32                # AES-256 key size in bytes.
ITERATIONS = 480000          # Number of iterations for PBKDF2 key derivation.
CHUNK_SIZE = 64 * 1024       # 64KB chunk size for processing large files.


class CryptoCore:
    """
    Handles the core cryptographic operations: encryption and decryption of files and folders.
    """
    def __init__(self, password, output_dir, shred_original=False):
        self.password = password
        self.output_dir = output_dir
        self.shred_original = shred_original

    def _derive_key(self, salt, iterations):
        """
        Derives a cryptographic key from the user's password using PBKDF2-HMAC-SHA256.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(self.password.encode('utf-8'))

    def _shred_path(self, path_to_shred):
        """
        Securely deletes a file or directory. For files, it overwrites the content with random data
        before deletion. For directories, it removes them recursively.
        """
        try:
            if os.path.isfile(path_to_shred):
                file_length = os.path.getsize(path_to_shred)
                with open(path_to_shred, "rb+") as f:
                    # Overwrite the file with random data in chunks.
                    for j in range(0, file_length, CHUNK_SIZE):
                        f.seek(j)
                        f.write(os.urandom(min(CHUNK_SIZE, file_length - j)))
                    f.flush()
                    os.fsync(f.fileno())
                time.sleep(0.1) # Small delay to ensure OS handles the file write.
                os.remove(path_to_shred)
            elif os.path.isdir(path_to_shred):
                shutil.rmtree(path_to_shred)
            return "" # Return empty string on success.
        except Exception as e:
            return f"Warning: Failed to securely shred '{os.path.basename(path_to_shred)}': {e}"

    def _encrypt_file_gcm(self, input_path, original_filename_str=None, shred_path=None, lock=None):
        """
        Encrypts a single file using AES-256-GCM.

        File Structure:
        [MAGIC_NUMBER] [VERSION] [ITERATIONS] [SALT] [NONCE] [FILENAME_LEN] [FILENAME] [CIPHERTEXT] [AUTH_TAG]
        """
        output_base_name = os.path.basename(original_filename_str or input_path) + ".ironcrypt"
        unique_id = str(uuid.uuid4())
        temp_output_path = os.path.join(self.output_dir, f"{output_base_name}.{unique_id}.tmp")

        try:
            original_filename = (original_filename_str or os.path.basename(input_path)).encode('utf-8')
            with open(input_path, 'rb') as f_in, open(temp_output_path, 'wb') as f_out:
                salt = os.urandom(SALT_SIZE)
                nonce = os.urandom(NONCE_SIZE)
                key = self._derive_key(salt, ITERATIONS)

                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
                encryptor = cipher.encryptor()

                # Write header information to the output file.
                f_out.write(MAGIC_NUMBER)
                f_out.write(struct.pack('>B', FILE_FORMAT_VERSION))
                f_out.write(struct.pack('>I', ITERATIONS))
                f_out.write(salt)
                f_out.write(nonce)
                f_out.write(struct.pack('>H', len(original_filename)))
                f_out.write(original_filename)

                # Encrypt the file content in chunks.
                while (chunk := f_in.read(CHUNK_SIZE)):
                    f_out.write(encryptor.update(chunk))

                f_out.write(encryptor.finalize())
                f_out.write(encryptor.tag) # Append the GCM authentication tag.
                f_out.flush()
                os.fsync(f_out.fileno())

            # Use a lock for thread-safe file renaming in parallel processing.
            if lock: lock.acquire()

            final_output_path = os.path.join(self.output_dir, output_base_name)
            if os.path.exists(final_output_path):
                # Avoid overwriting by creating a unique filename.
                base, ext = os.path.splitext(output_base_name)
                short_uuid = unique_id.split('-')[0]
                final_output_path = os.path.join(self.output_dir, f"{base}_{short_uuid}{ext}")
            os.rename(temp_output_path, final_output_path)

            if lock: lock.release()

            shred_warning = self._shred_path(shred_path) if self.shred_original and shred_path else ""
            success_msg = f"Successfully created '{os.path.basename(final_output_path)}'."
            if self.shred_original and not shred_warning:
                success_msg += f" Original '{os.path.basename(shred_path)}' was securely shredded."
            return (True, (success_msg, final_output_path))
        except Exception as e:
            return (False, f"Encryption failed: {e}")
        finally:
            if os.path.exists(temp_output_path):
                os.remove(temp_output_path)

    def _encrypt_folder_gcm(self, folder_path, lock=None):
        """
        Encrypts a folder by first archiving it as a ZIP file, then encrypting the archive.
        """
        temp_dir = os.path.join(self.output_dir, f"temp_zip_{uuid.uuid4()}")
        try:
            # Create a temporary ZIP archive of the folder.
            temp_zip_path = shutil.make_archive(os.path.join(temp_dir, "archive"), 'zip', folder_path)
            # Encrypt the created ZIP file.
            return self._encrypt_file_gcm(temp_zip_path, os.path.basename(folder_path), shred_path=folder_path, lock=lock)
        except Exception as e:
            return (False, f"Failed to archive folder: {e}")
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

    def _decrypt_and_verify_gcm(self, input_path, lock=None):
        """
        Decrypts a .ironcrypt file, verifies its integrity using the GCM tag,
        and extracts the original file or folder.
        """
        temp_decrypted_path = os.path.join(self.output_dir, f"decrypted_temp_{uuid.uuid4()}")
        try:
            with open(input_path, 'rb') as f:
                # Verify the magic number to ensure it's a valid file.
                if f.read(len(MAGIC_NUMBER)) != MAGIC_NUMBER:
                    return (False, "Invalid file format or not an IronCrypt file.")
                version = struct.unpack('>B', f.read(1))[0]
                if version > FILE_FORMAT_VERSION:
                    return (False, f"Unsupported file version ({version}).")

                # Read header metadata.
                iterations = struct.unpack('>I', f.read(4))[0]
                salt, nonce = f.read(SALT_SIZE), f.read(NONCE_SIZE)
                original_filename_len = struct.unpack('>H', f.read(2))[0]
                original_filename = f.read(original_filename_len).decode('utf-8')

                header_end = f.tell()
                f.seek(0, 2) # Seek to the end of the file.
                tag_start = f.tell() - TAG_SIZE
                ciphertext_size = tag_start - header_end
                if ciphertext_size < 0:
                    return (False, "Corrupted file structure.")

                f.seek(tag_start)
                tag = f.read(TAG_SIZE)
                f.seek(header_end)

                key = self._derive_key(salt, iterations)
                cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
                decryptor = cipher.decryptor()

                with open(temp_decrypted_path, 'wb') as f_out:
                    # Decrypt the ciphertext in chunks.
                    bytes_read = 0
                    while bytes_read < ciphertext_size:
                        chunk_to_read = min(CHUNK_SIZE, ciphertext_size - bytes_read)
                        chunk = f.read(chunk_to_read)
                        f_out.write(decryptor.update(chunk))
                        bytes_read += len(chunk)
                    f_out.write(decryptor.finalize()) # Verifies the authentication tag.

            # Use a lock for thread-safe file operations.
            if lock: lock.acquire()

            is_archive = zipfile.is_zipfile(temp_decrypted_path)
            final_output_path = os.path.join(self.output_dir, original_filename)
            if os.path.exists(final_output_path):
                # Avoid overwriting existing files/folders.
                base, ext = os.path.splitext(original_filename)
                final_output_path = os.path.join(self.output_dir, f"{base}_{uuid.uuid4().hex[:6]}{ext if not is_archive else ''}")

            if is_archive:
                shutil.unpack_archive(temp_decrypted_path, final_output_path, 'zip')
                result_message = "Folder successfully extracted."
            else:
                shutil.move(temp_decrypted_path, final_output_path)
                result_message = "File successfully decrypted."

            if lock: lock.release()
            return (True, (result_message, final_output_path))

        except InvalidTag:
            return (False, "Decryption failed: Incorrect password or corrupted file.")
        except Exception as e:
            return (False, f"A critical error occurred during decryption: {e}")
        finally:
            # Clean up temporary files.
            if os.path.exists(temp_decrypted_path):
                if os.path.isdir(temp_decrypted_path):
                    shutil.rmtree(temp_decrypted_path, ignore_errors=True)
                else:
                    os.remove(temp_decrypted_path)
