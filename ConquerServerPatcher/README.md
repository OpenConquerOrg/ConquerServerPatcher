# Conquer Server Patcher

A Windows desktop application for working with the RSA-protected DAT files and
embedded public key used by classic Conquer Online 2.0 clients.

The project is a C# / WPF implementation of the workflow provided by
[Cyano-CO/conquer-rsa-patcher](https://github.com/Cyano-CO/conquer-rsa-patcher).

## Compatibility

Conquer Server Patcher supports classic Conquer Online 2.0 clients from patch
**5095 through 6609**.

The following client versions are known to work:

- 5095
- 5187
- 5517
- 5615
- 6090
- 6609 (DX8 and DX9)

Clients older than 5095 do not use this RSA DAT workflow. Versions newer than
6609 are outside the scope of this project. Do not use the patcher with current
live-game binaries.

## Features

- Detects compatible original clients and clients already patched with the
  current key.
- Extracts and stores the original RSA public key from `Conquer.exe`.
- Generates a permanent 2048-bit RSA key pair once and reuses it.
- Patches the embedded RSA modulus without overwriting the original executable.
- Suggests `<name>Patched.exe` while allowing a custom output name.
- Optionally bypasses the `play.exe` launcher requirement.
- Decrypts RSA-protected DAT files with the original client key.
- Compresses and re-encrypts modified DAT files with the permanent private key.
- Uses a two-step interface with accessible labels, keyboard shortcuts, and
  clear status messages.

## Requirements

- Windows 10 or Windows 11, x64.
- .NET 10 SDK with the .NET desktop workload, or Visual Studio with WPF support.

## Build and run

Open `ConquerServerPatcher.slnx` in Visual Studio and set
`ConquerServerPatcher.Wpf` as the startup project.

From a terminal:

```powershell
dotnet build ConquerServerPatcher.slnx -c Release
dotnet run --project src/ConquerServerPatcher.Wpf
```

## Recommended workflow

1. Click **Choose client** and select the original `Conquer.exe`.
2. Confirm that the client is reported as compatible.
3. Review the suggested output name, such as `ConquerPatched.exe`.
4. Click **Apply patch**.
5. Use **Decrypt DAT** to decrypt the original RSA-protected `Server.dat`.
6. Edit the decrypted file.
7. Use **Encrypt DAT** to encrypt it with the permanent server key.
8. Back up the original DAT, then place the encrypted DAT and patched executable
   in the client directory.

The original executable is never overwritten. If an output file already exists,
the application creates a timestamped backup before replacing it.

## Key storage

The permanent key pair and the last extracted original client key are stored in:

```text
%LocalAppData%\ConquerServerPatcher\keys
```

Keep the private key safe. A client patched with the generated public key can
only read DAT files encrypted with the matching private key.

## DAT file limitations

This tool only works with DAT files that use the Conquer RSA file cipher. Other
DAT files may use the TQ cipher or another format and cannot be processed by
this application.

See the
[Conquer Online DAT format list](https://conquer-online.github.io/wiki/files/formats/dat.html)
and the
[RSA file cipher documentation](https://conquer-online.github.io/wiki/security/rsa.html)
for technical details.

## Technical overview

- RSA modulus size: 2048 bits
- Public exponent: 65537
- Ciphertext block size: 256 bytes
- Plaintext payload per block: 245 bytes
- Padding: PKCS#1 type 1
- Compression: GZip
- Client modulus representation: 64 `uint32` words
- Client obfuscation: rolling XOR beginning at index 17

## Safety

- Always work on backups.
- Re-encrypt every RSA-protected DAT required by a patched client.
- The optional `play.exe` bypass may not match unknown binary variants; failure
  to apply it does not prevent the RSA key patch.
- No Conquer binaries or third-party private keys are included.

## License

See [LICENSE](LICENSE).
