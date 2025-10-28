import argparse
import os
import sys
import getpass
from cryptocore import CryptoCore

def main():
    """
    Main function to handle command-line argument parsing and orchestrate
    the encryption/decryption process.
    """
    parser = argparse.ArgumentParser(
        description="IronCryptor: Encrypt/decrypt files and folders from the command line.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # --- Operation Mode Arguments (Mutually Exclusive) ---
    # The user must choose either encryption or decryption.
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument('-e', '--encrypt', dest='input_path_encrypt', metavar='PATH',
                            help='Path to the file or folder to encrypt.')
    mode_group.add_argument('-d', '--decrypt', dest='input_path_decrypt', metavar='PATH',
                            help='Path to the .ironcrypt file to decrypt.')

    # --- Optional Arguments ---
    parser.add_argument('-p', '--password', dest='password',
                        help='Password for the operation.\n(For security, it is recommended to omit this and enter the password when prompted.)')
    parser.add_argument('-o', '--output', dest='output_dir', default='.',
                        help='Output directory for the resulting files.\n(Default: current directory)')
    parser.add_argument('--shred', action='store_true',
                        help='Securely delete the original file/folder after encryption. USE WITH CAUTION!')

    args = parser.parse_args()

    # --- Password Handling ---
    # If the password is not provided as an argument, prompt the user securely.
    password = args.password
    if not password:
        try:
            password = getpass.getpass("Password: ")
            if not password:
                print("Error: Password cannot be empty.", file=sys.stderr)
                sys.exit(1)
        except (EOFError, KeyboardInterrupt):
            print("\nOperation cancelled.", file=sys.stderr)
            sys.exit(1)

    # --- Output Directory Validation ---
    # Create the output directory if it doesn't exist.
    if not os.path.isdir(args.output_dir):
        try:
            os.makedirs(args.output_dir)
            print(f"Created output directory: {args.output_dir}")
        except OSError as e:
            print(f"Error: Could not create output directory: {e}", file=sys.stderr)
            sys.exit(1)

    # --- Initialize CryptoCore ---
    core = CryptoCore(password, args.output_dir, args.shred)

    # --- Execute Encryption or Decryption ---
    if args.input_path_encrypt:
        input_path = args.input_path_encrypt
        if not os.path.exists(input_path):
            print(f"Error: Input path not found -> {input_path}", file=sys.stderr)
            sys.exit(1)

        print(f"Encrypting: {os.path.basename(input_path)}...")
        if os.path.isfile(input_path):
            success, result = core._encrypt_file_gcm(input_path, shred_path=input_path)
        else:  # It's a directory
            success, result = core._encrypt_folder_gcm(input_path)

    elif args.input_path_decrypt:
        input_path = args.input_path_decrypt
        if not os.path.isfile(input_path):
            print(f"Error: Input must be a file -> {input_path}", file=sys.stderr)
            sys.exit(1)
        if not input_path.lower().endswith('.ironcrypt'):
            print(f"Warning: File does not have a '.ironcrypt' extension, but attempting anyway.", file=sys.stderr)

        print(f"Decrypting: {os.path.basename(input_path)}...")
        success, result = core._decrypt_and_verify_gcm(input_path)

    # --- Display Final Result ---
    if success:
        message, output_path = result
        print(f"\nOperation Successful!")
        print(f"  Message: {message}")
        print(f"  Output Path: {os.path.abspath(output_path)}")
    else:
        print(f"\nOperation Failed!", file=sys.stderr)
        print(f"  Error: {result}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
