# ConquerServerPatcher — WPF / .NET 10

Primera versión completa en C# del flujo de `conquer-rsa-patcher`.

## Funciones

- Analiza `Conquer.exe` y localiza las 64 palabras del módulo RSA.
- Extrae la clave pública original a PEM.
- Genera claves RSA de 2048 bits.
- Descifra DAT mediante RSA público + PKCS#1 tipo 1 + GZip.
- Cifra DAT mediante GZip + PKCS#1 tipo 1 + operación RSA privada.
- Parchea el módulo RSA dentro del ejecutable.
- Aplica opcionalmente el bypass de `play.exe` para patrones 5095–6609.
- Mantiene el archivo original intacto al usar un destino distinto y crea backup si sobrescribes un destino existente.

## Requisitos

- Windows 10/11 x64.
- Visual Studio 2026 o SDK .NET 10 con workload de escritorio .NET.

## Abrir y ejecutar

1. Abre `ConquerServerPatcher.slnx`.
2. Establece `ConquerServerPatcher.Wpf` como proyecto de inicio.
3. Compila en `Release`.

Por terminal:

```powershell
dotnet build ConquerServerPatcher.slnx -c Release
dotnet run --project src/ConquerServerPatcher.Wpf
```

## Flujo recomendado

1. En **Cliente**, selecciona el `Conquer.exe` original y pulsa **Analizar cliente**.
2. Pulsa **Extraer clave pública** y descifra los DAT originales desde **Archivos DAT**.
3. Genera un nuevo par de claves desde **Claves**.
4. Parchea una copia del cliente usando la nueva clave pública.
5. Cifra todos los DAT modificados usando la nueva clave privada.
6. Copia los DAT cifrados junto al cliente parcheado.

## Advertencias

- Prueba siempre con copias; un error de parche o un DAT sin recifrar puede impedir el arranque.
- Al cambiar la clave del cliente, los DAT RSA originales dejarán de ser legibles por ese ejecutable.
- El bypass de `play.exe` es opcional. Si no reconoce los patrones, el módulo RSA seguirá parcheándose.
- No se incluye ningún binario de Conquer ni claves privadas externas.

## Base técnica portada

La implementación reproduce el algoritmo del repositorio original: módulo de 2048 bits dividido en 64 `uint32`, ofuscación XOR empezando en el índice 17, bloques RSA de 256 bytes, chunks de 245 bytes y exponente público 65537.
