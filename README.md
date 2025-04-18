# 📦 filecrypt

**filecrypt** is a standalone Python utility to compress and encrypt or decrypt files and directories.  
It uses AES-256-CBC encryption and allows progress display during operations.  

You can generate a key automatically, provide one in hex, or use a key file. The tool works via command-line arguments.

---

## ⚙️ Quick Setup with `uv`

This project uses [`uv`](https://github.com/astral-sh/uv) for fast and reproducible dependency management.

1️⃣ Create a virtual environment:
```bash
uv venv .venv
```

2️⃣ Install dependencies:
```bash
uv sync --no-install-project
```

---

## 🔐 Usage

**Encrypt a file or directory:**
```bash
uv run python filecrypt.py --encrypt -i /path/to/input -o /path/to/output -p
```

**Decrypt an encrypted file:**
```bash
uv run python filecrypt.py --decrypt -i /path/to/encrypted_file -o /output/directory -k /path/to/keyfile -p
```

**Arguments:**
- `--encrypt` : Encrypt mode.
- `--decrypt` : Decrypt mode.
- `-i`, `--input` : Input file or directory.
- `-o`, `--output` : Output file or directory.
- `-k`, `--key` : Key file or hex string (optional for encryption, required for decryption).
- `-p`, `--progress` : Show progress during processing.

---

## 📦 Build Standalone Executable

Use `PyInstaller` via `uv` to generate a single-file executable:

```bash
uv run pyinstaller --clean --onefile filecrypt.py
```

The resulting binary will be available in the `dist/` folder.

---

## 📑 Dependencies

- `cryptography`
- `pyinstaller`
- `uv` (for dependency management)

Dependencies are listed in `pyproject.toml`.

---

## 📌 Notes

- The script automatically saves encryption keys in your system's temporary directory.
- It uses a timestamp and OS tag for versioned output filenames.
- Encrypted files contain the IV prepended to the content.
- Only AES-256-CBC with PKCS7 padding is supported.

---

## 🖥️ Tested On

- Linux
- Windows

---

## 📜 License
...