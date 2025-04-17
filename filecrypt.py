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

# Tamaño de bloque para lectura/escritura
CHUNK_SIZE = 64 * 1024  # 64 KB

# Obtener timestamp y sistema para versionado
def get_version_tag(file_name: str):
    now = datetime.now().strftime('%m%d%Y_%H%M%S')
    os_tag = platform.system().lower()
    return f"{file_name}_{now}_{os_tag}"

# == Gestión de clave ==
def generate_key():
    """Genera clave AES-256 aleatoria (32 bytes)."""
    return secrets.token_bytes(32)

def save_key(key: bytes, tag: str) -> str:
    """Guarda clave en ruta temporal con versionado y retorna la ruta."""
    temp = tempfile.gettempdir()
    key_filename = f"filecrypt_key_{tag}.key"
    key_path = os.path.join(temp, key_filename)
    with open(key_path, 'wb') as f:
        f.write(key)
    return key_path

def load_key(path: str) -> bytes:
    """Carga clave desde archivo."""
    with open(path, 'rb') as f:
        return f.read()

# == Compresión ==
def compress(input_path: str, zip_path: str, show_progress: bool):
    """Comprime archivo o directorio en ZIP."""
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
                print(f'[+] Comprimido {idx}/{total}: {arcname}')

# == Cifrado por bloques ==
def encrypt_file(input_path: str, output_path: str, key: bytes, show_progress: bool):
    """Cifra archivo con AES-256-CBC en bloques y guarda IV al inicio."""
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
                print(f'[+] Cifrando: {processed/total_size*100:.2f}%')
        padded = padder.finalize()
        enc = encryptor.update(padded) + encryptor.finalize()
        fout.write(enc)

# == Descifrado por bloques ==
def decrypt_file(input_path: str, output_path: str, key: bytes, show_progress: bool):
    """Descifra archivo AES-256-CBC en bloques, espera IV al inicio."""
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
                    print(f'[+] Descifrando: {processed/total_size*100:.2f}%')
            dec = decryptor.finalize()
            unp = unpadder.update(dec) + unpadder.finalize()
            fout.write(unp)

# == Decompresión ==
def decompress(zip_path: str, output_dir: str, show_progress: bool):
    """Extrae ZIP en carpeta."""
    with zipfile.ZipFile(zip_path, 'r') as zf:
        members = zf.namelist()
        total = len(members)
        for idx, member in enumerate(members, 1):
            zf.extract(member, output_dir)
            if show_progress:
                print(f'[+] Descomprimido {idx}/{total}: {member}')

# == Lógica principal ==
def main():
    parser = argparse.ArgumentParser(description='filecrypt: comprime y cifra/descifra archivos y directorios')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--encrypt', action='store_true', help='Modo cifrar')
    group.add_argument('--decrypt', action='store_true', help='Modo descifrar')
    parser.add_argument('-i', '--input', required=True, help='Ruta de entrada')
    parser.add_argument('-o', '--output', help='Ruta de salida (archivo o carpeta). Si no se especifica, se usa el directorio actual')
    parser.add_argument('-k', '--key', help='Archivo de clave o clave en hex (opcional para encrypt; obligatorio para decrypt)')
    parser.add_argument('-p', '--progress', action='store_true', help='Mostrar progreso')
    args = parser.parse_args()

    # Validar input
    if not os.path.exists(args.input):
        print(f"Error: Ruta de entrada no existe: {args.input}")
        sys.exit(1)

    # Tag para versionado
    tag = get_version_tag()

    # Determinar ruta de salida
    if args.output:
        out_path = args.output
    else:
        out_path = os.getcwd()
    if os.path.isdir(out_path) or out_path.endswith(os.sep):
        base_name = Path(args.input).stem
        if args.encrypt:
            default_name = f"{base_name}_{tag}_encrypted.bin"
        else:
            default_name = f"{base_name}_{tag}_decrypted.zip"
        out_path = os.path.join(out_path, default_name)
    args.output = out_path

    if args.encrypt:
        tmp_zip = os.path.join(tempfile.gettempdir(), f'filecrypt_temp_{tag}.zip')
        print('[*] Iniciando compresión...')
        compress(args.input, tmp_zip, args.progress)
        print(f'[*] Comprimido a: {tmp_zip}')

        # Gestionar clave
        if args.key:
            if os.path.isfile(args.key):
                key = load_key(args.key)
                key_path = args.key
            else:
                try:
                    key = bytes.fromhex(args.key)
                    key_path = save_key(key, tag)
                except ValueError:
                    print('Error: clave hex inválida')
                    sys.exit(1)
        else:
            key = generate_key()
            key_path = save_key(key, tag)
        print(f'[*] Clave en: {key_path}')

        print('[*] Iniciando cifrado...')
        encrypt_file(tmp_zip, args.output, key, args.progress)
        print(f'[*] Archivo cifrado: {args.output}')
        os.remove(tmp_zip)

    else:  # decrypt
        # Clave obligatoria
        if not args.key:
            print('Error: se requiere --key para descifrar')
            sys.exit(1)
        if os.path.isfile(args.key):
            key = load_key(args.key)
        else:
            try:
                key = bytes.fromhex(args.key)
            except ValueError:
                print('Error: clave hex inválida')
                sys.exit(1)

        tmp_zip = os.path.join(tempfile.gettempdir(), f'filecrypt_temp_dec_{tag}.zip')
        print('[*] Iniciando descifrado...')
        decrypt_file(args.input, tmp_zip, key, args.progress)
        print(f'[*] ZIP descifrado: {tmp_zip}')

        print('[*] Iniciando descompresión...')
        decompress(tmp_zip, args.output, args.progress)
        print(f'[*] Archivos extraídos en: {args.output}')
        os.remove(tmp_zip)

if __name__ == '__main__':
    main()
