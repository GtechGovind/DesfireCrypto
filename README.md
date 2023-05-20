# DesfireCrypto

DesfireCrypto is a C++ class that provides cryptographic functionalities for DESFire cards. It includes encryption, decryption, initialization of the Cipher-based Message Authentication Code (CMAC), and other utility functions.

## Functions

### generateSubkeys
```cpp
void generateSubkeys();
```
This function generates key0, key1, and key2 for DESFire. It performs the following steps:
1. Generate key0, key1, and key2.
2. Encrypt 16 bytes of 0x00 with the key.
3. Left shift key0 by 1 bit and store it in key1.
4. If the Most Significant Bit (MSB) of key0 is 0x80, then key1 = (key0 << 1) ^ 0x87.
5. Left shift key1 by 1 bit and store it in key2.
6. If the MSB of key1 is 0x80, then key2 = (key1 << 1) ^ 0x87.

### setIv
```cpp
void setIv(const vector<uint8_t> &_iv);
```
This function sets the Initialization Vector (IV) for encryption and decryption. The IV is obtained during authentication.

### encryptAes
```cpp
vector<uint8_t> encryptAes(vector<uint8_t> &data, const vector<uint8_t> &key, const vector<uint8_t> &iv);
```
This function encrypts the provided data using AES-128 algorithm. It takes the data, encryption key, and IV as inputs and returns the encrypted data as a vector of bytes.

### decryptAes
```cpp
vector<uint8_t> decryptAes(vector<uint8_t> &data, const vector<uint8_t> &key, const vector<uint8_t> &iv);
```
This function decrypts the provided data using AES-128 algorithm. It takes the data, decryption key, and IV as inputs and returns the decrypted data as a vector of bytes.

### initCMAC
```cpp
void initCMAC(const vector<uint8_t> &_key, const vector<uint8_t> &_iv);
```
This function initializes the Cipher-based Message Authentication Code (CMAC) with the provided key and IV. It is called during the authentication process.

### getCMAC
```cpp
vector<uint8_t> getCMAC(const vector<uint8_t> &_data);
```
This function calculates the CMAC for the provided data. It performs the following steps:
1. Checks if padding is required (`isPaddingRequired = dataLen % AES_BLOCK_SIZE != 0`).
2. Calculates the number of blocks (`numberOfBlocks = isPaddingRequired ? dataLen / AES_BLOCK_SIZE + 1 : dataLen / AES_BLOCK_SIZE`).
3. Splits the data into blocks, each of size 16 bytes (for AES).
4. If padding is required, adds padding to the last block (`lastBlock.push_back(0x80); lastBlock.resize(AES_BLOCK_SIZE, 0x00);`).
5. If `isPaddingRequired` is true, XORs the last block with key2; otherwise, XORs it with key1.
6. For each block, XORs it with the previous IV obtained in the last process (`xorVec(blocks[i], iv, blocks[i]);`).
7. Encrypts the XORed block with AES-128 using the key and IV (`aes.EncryptCBC(blocks[i], key, iv);`). The IV used for encryption should be all zeros.
8. Updates the IV with the encrypted block.
9. Returns the last block of the IV as DesfireCrypto, as only the first 8