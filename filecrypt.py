#!/usr/bin/env python3
import os
import sys
import argparse
import zipfile
import tempfile
from pathlib import Path
from datetime import datetime
import platform
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import secrets

# Block size for reading/writing files (64 KB)
CHUNK_SIZE = 64 * 1024  

def get_version_tag():
    """
    Generate a versioning tag based on the current timestamp and system platform.

    Returns:
        str: Tag string in the format 'MMDDYYYY_HHMMSS_platform'.
    """
    now = datetime.now().strftime('%m%d%Y_%H%M%S')
    os_tag = platform.system().lower()
    return f"{now}_{os_tag}"

# == Key management ==

def generate_key():
    """
    Generate a random 256-bit AES encryption key.

    Returns:
        bytes: A 32-byte random key.
    """
    return secrets.token_bytes(32)

def save_key(key: bytes, tag: str, base_name: str) -> str:
    """
    Save the given key to a temporary file with a versioned filename.

    Args:
        key (bytes): AES key to save.
        tag (str): Version tag for the filename.
        base_name (str): Base name for the key file.

    Returns:
        str: Path to the saved key file.
    """
    temp = tempfile.gettempdir()
    key_filename = f"{base_name}_{tag}.key"
    key_path = os.path.join(temp, key_filename)
    with open(key_path, 'wb') as f:
        f.write(key)
    return key_path

def load_key(path: str) -> bytes:
    """
    Load an AES key from a file.

    Args:
        path (str): Path to the key file.

    Returns:
        bytes: The loaded key.
    """
    with open(path, 'rb') as f:
        return f.read()

# == Compression ==

def compress(input_path: str, zip_path: str, show_progress: bool):
    """
    Compress a file or directory into a ZIP archive.

    Args:
        input_path (str): Path to the input file or directory.
        zip_path (str): Path for the resulting ZIP file.
        show_progress (bool): Whether to display progress during compression.
    """
    if os.path.isfile(input_path):
        files = [input_path]
        base_dir = os.path.dirname(input_path)
    else:
        files = []
        for root, _, filenames in os.walk(input_path):
            for name in filenames:
                files.append(os.path.join(root, name))
        base_dir = input_path
    total = len(files)
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for idx, filepath in enumerate(files, 1):
            arcname = os.path.relpath(filepath, base_dir)
            zf.write(filepath, arcname)
            if show_progress:
                print(f'[+] Compressed {idx}/{total}: {arcname}')

# == Block encryption ==

def encrypt_file(input_path: str, output_path: str, key: bytes, show_progress: bool):
    """
    Encrypt a file using AES-256-CBC with PKCS7 padding. The IV is stored at the beginning of the output file.

    Args:
        input_path (str): Path to the input file.
        output_path (str): Path to the encrypted output file.
        key (bytes): AES encryption key.
        show_progress (bool): Whether to display encryption progress.
    """
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    total_size = os.path.getsize(input_path)
    processed = 0
    with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
        fout.write(iv)
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            padded = padder.update(chunk)
            enc = encryptor.update(padded)
            fout.write(enc)
            processed += len(chunk)
            if show_progress:
                print(f'[+] Encrypting: {processed / total_size * 100:.2f}%')
        padded = padder.finalize()
        enc = encryptor.update(padded) + encryptor.finalize()
        fout.write(enc)

# == Block decryption ==

def decrypt_file(input_path: str, output_path: str, key: bytes, show_progress: bool):
    """
    Decrypt a file encrypted with AES-256-CBC. The IV is expected to be stored at the beginning of the file.

    Args:
        input_path (str): Path to the encrypted file.
        output_path (str): Path for the decrypted output file.
        key (bytes): AES decryption key.
        show_progress (bool): Whether to display decryption progress.
    """
    with open(input_path, 'rb') as fin:
        iv = fin.read(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        total_size = os.path.getsize(input_path) - 16
        processed = 0
        with open(output_path, 'wb') as fout:
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                dec = decryptor.update(chunk)
                unp = unpadder.update(dec)
                fout.write(unp)
                processed += len(chunk)
                if show_progress:
                    print(f'[+] Decrypting: {processed / total_size * 100:.2f}%')
            dec = decryptor.finalize()
            unp = unpadder.update(dec) + unpadder.finalize()
            fout.write(unp)

# == Decompression ==

def decompress(zip_path: str, output_dir: str, show_progress: bool):
    """
    Extract the contents of a ZIP archive into a specified directory.

    Args:
        zip_path (str): Path to the ZIP archive.
        output_dir (str): Destination directory.
        show_progress (bool): Whether to display extraction progress.
    """
    with zipfile.ZipFile(zip_path, 'r') as zf:
        members = zf.namelist()
        total = len(members)
        for idx, member in enumerate(members, 1):
            zf.extract(member, output_dir)
            if show_progress:
                print(f'[+] Extracted {idx}/{total}: {member}')

# == Main program logic ==

def main():
    """
    Command-line interface for compressing and encrypting / decrypting and extracting files and directories.
    """
    parser = argparse.ArgumentParser(description='filecrypt: compress, encrypt/decrypt files and directories.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--encrypt', action='store_true', help='Enable encryption mode.')
    group.add_argument('--decrypt', action='store_true', help='Enable decryption mode.')
    parser.add_argument('-i', '--input', required=True, help='Input file or directory path.')
    parser.add_argument('-o', '--output', help='Output file or directory path. Defaults to the current directory.')
    parser.add_argument('-k', '--key', help='Path to the key file or hex key string. Required for decryption.')
    parser.add_argument('-p', '--progress', action='store_true', help='Show progress during operations.')
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"Error: Input path does not exist: {args.input}")
        sys.exit(1)

    tag = get_version_tag()

    if args.output:
        out_path = args.output
    else:
        out_path = os.getcwd()
    base_name = Path(args.input).stem
    if os.path.isdir(out_path) or out_path.endswith(os.sep):
        default_name = f"{base_name}_{tag}_encrypted.bin" if args.encrypt else f"{base_name}_{tag}_decrypted.zip"
        out_path = os.path.join(out_path, default_name)
    args.output = out_path

    if args.encrypt:
        tmp_zip = os.path.join(tempfile.gettempdir(), f'filecrypt_temp_{tag}.zip')
        print('[*] Starting compression...')
        compress(args.input, tmp_zip, args.progress)
        print(f'[*] Compressed to: {tmp_zip}')

        if args.key:
            if os.path.isfile(args.key):
                key = load_key(args.key)
                key_path = args.key
            else:
                try:
                    key = bytes.fromhex(args.key)
                    key_path = save_key(key, tag, base_name)
                except ValueError:
                    print('Error: Invalid hex key format.')
                    sys.exit(1)
        else:
            key = generate_key()
            key_path = save_key(key, tag, base_name)
        print(f'[*] Key saved to: {key_path}')

        print('[*] Starting encryption...')
        encrypt_file(tmp_zip, args.output, key, args.progress)
        print(f'[*] Encrypted file: {args.output}')
        os.remove(tmp_zip)

    else:
        if not args.key:
            print('Error: --key is required for decryption.')
            sys.exit(1)
        if os.path.isfile(args.key):
            key = load_key(args.key)
        else:
            try:
                key = bytes.fromhex(args.key)
            except ValueError:
                print('Error: Invalid hex key format.')
                sys.exit(1)

        tmp_zip = os.path.join(tempfile.gettempdir(), f'filecrypt_temp_dec_{tag}.zip')
        print('[*] Starting decryption...')
        decrypt_file(args.input, tmp_zip, key, args.progress)
        print(f'[*] Decrypted ZIP: {tmp_zip}')

        print('[*] Starting extraction...')
        decompress(tmp_zip, args.output, args.progress)
        print(f'[*] Files extracted to: {args.output}')
        os.remove(tmp_zip)

if __name__ == '__main__':
    main()
