# DesfireCMAC

DesfireCMAC is a C++ library that provides an implementation of the CMAC (Cipher-based Message Authentication Code) algorithm using AES (Advanced Encryption Standard) encryption.

## Table of Contents
- [Introduction](#introduction)
- [Installation](#installation)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Author](#author)

## Introduction

DesfireCMAC is designed to generate a CMAC for a given data input using AES encryption. It utilizes the AES algorithm to generate subkeys and perform the necessary operations to calculate the CMAC.

The library provides the following functions:
- `initCMAC`: Initializes the CMAC algorithm with a key and initialization vector (IV).
- `getCMAC`: Calculates the CMAC for a given data input.
- `leftShift`: Performs a left shift operation on a vector.
- `vecPrint`: Prints a vector in hexadecimal format.
- `xorVec`: Performs an XOR operation between two vectors.

## Installation

To use DesfireCMAC in your project, follow these steps:

1. Clone the DesfireCMAC repository from GitHub: `git clone https://github.com/GtechGovind/DesfireCMAC.git`.
2. Include the `CMAC.h` header file in your C++ source code.
3. Make sure to link against the required dependencies, such as the AES library.

## Usage

Here's an example of how to use the DesfireCMAC library:

```cpp
#include "CMAC.h"

int main() {
    // Initialize CMAC with a key and IV
    vector<uint8_t> key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    vector<uint8_t> iv = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    CMAC cmac;
    cmac.initCMAC(key, iv);

    // Calculate CMAC for data
    vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
    vector<uint8_t> cmacResult = cmac.getCMAC(data);

    // Print the CMAC
    CMAC::vecPrint("CMAC", cmacResult);

    return 0;
}
```

## API Reference

### CMAC Class

#### `void initCMAC(const vector<uint8_t>& _key, const vector<uint8_t>& _iv)`

Initializes the CMAC algorithm with a key and IV.

- `_key`: The key for CMAC initialization.
- `_iv`: The initialization vector for CMAC initialization.

#### `vector<uint8_t> getCMAC(const vector<uint8_t>& _data)`

Calculates the CMAC for a given data input.

- `_data`: The input data for which the CMAC is to be calculated.
- Returns: The calculated CMAC as a vector of bytes.

#### `static void leftShift(const vector<uint8_t>& inputBuffer, vector<uint8_t>& outputBuffer)`

Performs a left shift operation on a vector.

- `inputBuffer`: The input vector to be left-shifted.
- `outputBuffer`: The output vector to store the left-shifted result.

#### `static void vecPrint(const string& message, const vector<unsigned char>& data)`

Prints a vector in hexadecimal format.

- `message`: The message to be printed before the vector.
- `data`: The

 vector to be printed.

#### `static void xorVec(const vector<uint8_t>& vector1, const vector<uint8_t>& vector2, vector<uint8_t>& result)`

Performs an XOR operation between two vectors and stores the result in a third vector.

- `vector1`: The first vector for XOR operation.
- `vector2`: The second vector for XOR operation.
- `result`: The resultant vector to store the XOR result.

## Author

DesfireCMAC is developed by Govind Yadav.
