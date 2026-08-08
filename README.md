# DesfireCrypto

A small C++17 implementation of the cryptographic building blocks used by MIFARE DESFire integrations: AES-CBC encryption and decryption, AES-CMAC subkey generation, DESFire-style truncated CMAC output, CRC-32, and byte-vector helpers.

The repository is intentionally compact so the byte-level operations remain inspectable.

## What it provides

- AES-128 encryption and decryption
- AES-CMAC generation with the first eight bytes returned for DESFire workflows
- CMAC support for empty, single-block, and multi-block messages
- Configurable session IV
- DESFire CRC-32 helper
- CMake library, example executable, and CTest target

## Build and test

Requirements: a C++17 compiler and CMake 3.25 or newer.

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

The tests use the AES-CMAC examples from NIST SP 800-38B, truncated to the eight-byte value returned by `getCMAC()`.

## Example

```cpp
#include <cstdint>
#include <vector>

#include "desfire_crypto/DesfireCrypto.h"

int main() {
    DesfireCrypto crypto;

    std::vector<uint8_t> key = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    std::vector<uint8_t> iv(16, 0x00);
    std::vector<uint8_t> message = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };

    crypto.initCMAC(key, iv);
    crypto.generateSubkeys();
    const auto cmac = crypto.getCMAC(message);
}
```

`getCMAC()` updates the object's IV as blocks are processed. Create a new instance or call `setIv()` when starting an independent calculation.

## API overview

| Method | Purpose |
| --- | --- |
| `initCMAC(key, iv)` | Initialize AES-CMAC state with a 16-byte key and IV |
| `generateSubkeys()` | Derive the two AES-CMAC subkeys |
| `getCMAC(data)` | Return the first eight bytes of the calculated CMAC |
| `setIv(iv)` | Replace the current session IV |
| `encryptAes(data, key, iv)` | AES-CBC encryption |
| `decryptAes(data, key, iv)` | AES-CBC decryption |
| `crc32(data, length, output)` | Calculate the four-byte CRC value |

## Security status

This implementation has not received an independent security audit. Validate it against the requirements and test vectors for your card/application profile before using it in production or for key-management operations. Do not log keys, derived subkeys, or session IVs.

## License

[MIT](LICENSE) © Govind Yadav
