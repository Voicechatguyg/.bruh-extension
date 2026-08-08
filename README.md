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

## bruh hub v0.1 Commands

`bruh hub v0.1` is a simple terminal-based tool with no interactive prompts. It only supports the v0.1 `.bruh` container format.

| Command | Usage | Description |
|---|---|---|
| `pack` | `bruh hub v0.1.exe pack <input_file> [output_file]` | Packs a single file into a `.bruh` container. If `output_file` is omitted, the tool writes `<input_file>.bruh`. |
| `unpack` | `bruh hub v0.1.exe unpack <bruh_file> [output_directory]` | Extracts the contained file from a `.bruh` archive. If `output_directory` is omitted, the current working directory is used. |
| `license` | `bruh hub v0.1.exe license` | Prints the GPLv3 license notice included with bruh hub. |

### Examples

Pack a file:

```bash
bruh hub v0.1.exe pack example.txt
```

Unpack a file:

```bash
bruh hub v0.1.exe unpack example.txt.bruh
```

Print license information:

```bash
bruh hub v0.1.exe license
```

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

### v0.3.5
- Added legacy `.bruh` file support for v0.1 and v0.2 files

If you encrypt a file with a password, dont not lose the password silly.
There is no password recovery.

## Usage

Download the latest release and run:

`bruh hub v0.3.5.exe`

Follow the prompts to pack or unpack files.

## Your Rights Under GPLv3

**bruh hub v0.3.5 is Free Software.**
It is licensed under the **GNU General Public License v3.0 (GPLv3)**, a "copyleft" license designed to protect users' freedom to use, study, modify, and redistribute software.

## What This Means For YOU — The 4 Freedoms

1. **Use it** — You can run bruh hub for any purpose, including personal, educational, commercial, or other uses.

2. **Study it** — The source code is available so you can understand how bruh hub works, inspect it, and learn from it.

3. **Redistribute it** — You can share copies with friends, publish it online, or even sell copies of it.

4. **Modify it** — You can fork it, improve it, modify it, or even create something like "BRUH PRO" if you want.

## The GPLv3 Requirements

Freedom comes with responsibilities.

If you redistribute bruh hub or a modified version, you must follow the requirements of the GPLv3 license. This includes:

* Keeping the GPLv3 license included.
* Providing access to the corresponding source code when required.
* Clearly indicating changes you made.
* Keeping modified versions under the GPLv3 license when distributing them.

The GPL allows you to share and modify this software, but it also ensures that these same freedoms are preserved for future users.

---

# If You Receive a Legal Threat

Example:

> "Company X sells this software for $20. You shared it for free. Remove it immediately."

A claim like this may misunderstand how GPLv3 works.

When software is released under GPLv3, recipients receive permission to use, modify, and redistribute it, as long as they follow the license requirements. A copyright holder cannot simply remove those permissions from people who already received the software under GPLv3.

## What To Do

1. **Do not panic.**
   Check whether you are following the GPLv3 requirements.

2. **Review the license.**
   The GPLv3 license included with bruh hub explains your rights and responsibilities.

3. **Ask for help if needed.**
   Free software organizations can provide information about GPL-related issues:

   * Software Freedom Conservancy:
     https://sfconservancy.org/copyleft

   * Free Software Foundation licensing information:
     https://www.fsf.org/licensing

4. **Consider professional legal advice for serious disputes.**
   The author of bruh hub is not a lawyer and cannot provide legal advice.

---

# About Modified or Unauthorized Versions

The GPLv3 allows people to create modified versions of bruh hub.

However, modified versions must still follow the GPLv3 license.

Examples of possible GPL violations include:

* Removing required copyright notices.
* Distributing modified versions without providing required source code.
* Adding restrictions that prevent users from exercising GPL rights.

If you find a version of bruh hub that appears to violate the GPLv3:

1. Do not assume it is legitimate.
2. Check whether the GPLv3 requirements are being followed.
3. Contact the project author or an appropriate free software organization for guidance.

---

## Disclaimer

The author of bruh hub is not a lawyer.
This section is provided as general information about the GPLv3 license and is not legal advice.

For the complete legal terms, read the official GPLv3 license included with this project:

https://www.gnu.org/licenses/gpl-3.0.html
