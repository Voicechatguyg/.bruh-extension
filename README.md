# .bruh extension

because apparently the world needed another file type.

`.bruh` is a custom file format designed to package files into a single container with optional encryption.

## Features

- Custom `.bruh` file format
- Pack and unpack files
- Versioned file format system
- AES-256-GCM encryption (v0.3+)
- Password-based key derivation using PBKDF2 (v0.3+)

## Versions

### v0.1
- Initial release
- Basic `.bruh` file packing/unpacking
- Command-line arguments (`pack` and `unpack`)
- Only supports v0.1 `.bruh` files
- No encryption

### v0.2
- Added interactive CLI
- No longer requires command-line arguments for normal use
- Added support for reading older `.bruh` versions
- Improved user experience

### v0.3
- Added password-protected encryption
- Uses AES-256-GCM authenticated encryption
- Uses PBKDF2 with per-file salts for key derivation
- Added stronger payload validation

⚠️ If you encrypt a file with a password, do not lose the password.
There is no password recovery.

## Usage

Download the latest release and run:

`bruh hub v0.3.exe`

Follow the prompts to pack or unpack files.

## License

See `LICENSE` for details.