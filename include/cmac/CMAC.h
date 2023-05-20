#pragma once

#include "../aes/AES.h"

using namespace std;

class CMAC {

    private:
    AES aes;
    vector<uint8_t> key;
    vector<uint8_t> key1;
    vector<uint8_t> key2;
    vector<uint8_t> iv;

    /**
     * @name generateSubkeys
     * @details 1. Generate key0, key1, key2
     * @details 2. Encrypt 16 bytes of 0x00 with key
     * @details 3. Left shift key0 by 1 bit and store in key1
     * @details 4. If MSB of key0 is 0x80, then key1 = (key0 << 1) ^ 0x87
     * @details 5. Left shift key1 by 1 bit and store in key2
     * @details 6. If MSB of key1 is 0x80, then key2 = (key1 << 1) ^ 0x87
     * @return void
    */
    void generateSubkeys();

    public:

    /**
     * @name initCMAC
     * @details 1. Initialize AES with key and iv
     * @details 2. Generate subkeys
     * @param _key = Session obtained during authentication
     * @param _iv = IV obtained during authentication
     * @return void
    */
    void initCMAC(const vector<uint8_t>& _key, const vector<uint8_t>& _iv);

    /**
     * @name getCMAC
     * @details 1. Calculate if padding is required or not [ isPaddingRequired = dataLen % AES_BLOCK_SIZE != 0 ]
     * @details 2. Calculate number of blocks [ numberOfBlocks = isPaddingRequired ? dataLen / AES_BLOCK_SIZE + 1 : dataLen / AES_BLOCK_SIZE ]
     * @details 3. Split data into blocks each of size 16 bytes [ FOR AES ]
     * @details 4. If padding is required, add padding to last block [ lastBlock.push_back(0x80); lastBlock.resize(AES_BLOCK_SIZE, 0x00); ]
     * @details 5. if isPaddingRequired is true, xor last block with key2 else xor last block with key1
     * @details 6. For each block, xor with previous IV obtain in last process. [ xorVec(blocks[i], iv, blocks[i]); ]
     * @details 7. Encrypt xor'ed block with AES-128 [ aes.EncryptCBC(blocks[i], key, iv); ] iv used for encryption should be all zero's
     * @details 8. Update iv with encrypted block
     * @details 9. Return last block of iv as CMAC only first 8 bytes are required
     * @param _data
     * @return cmac.
    */
    vector<uint8_t> getCMAC(const vector<uint8_t>& _data);

    /**
     * @name leftShift
     * @details 1. Left shift inputBuffer by 1 bit and store in outputBuffer
     * @details 2. If MSB of inputBuffer is 0x80, then outputBuffer = (inputBuffer << 1) ^ 0x87
     * @param inputBuffer = Input buffer
     * @param outputBuffer = Output buffer
     * @return void
    */
    static void leftShift(const vector<uint8_t>& inputBuffer, vector<uint8_t>& outputBuffer) {
        outputBuffer.clear();
        outputBuffer.resize(inputBuffer.size());
        uint8_t overflow = 0;
        for (int i = inputBuffer.size() - 1; i >= 0; --i) {
            outputBuffer[i] = inputBuffer[i] << 1;
            outputBuffer[i] |= overflow;
            overflow = (inputBuffer[i] & 0x80) ? 0x01U : 0x00U;
        }
    }

    /**
     * @name vecPrint
     * @details 1. Print vector in hex format
     * @param message = Message to be printed before vector
     * @param data = Vector to be printed
     * @return void
    */
    static void vecPrint(const string& message, const vector<unsigned char>& data) {
        cout << message << " -> \t\t";
        for (unsigned char i : data) {
            printf("%02X", i);
        }
        cout << " | " << data.size() << endl;
    }


    /**
     * @name xorVec
     * @details 1. Xor two vectors and store result in third vector
     * @param vector1 = First vector
     * @param vector2 = Second vector
     * @param result = Resultant vector
    */
    static void xorVec(const vector<uint8_t>& vector1, const vector<uint8_t>& vector2, vector<uint8_t>& result) {
        size_t size = min(vector1.size(), vector2.size());
        result.clear();
        result.reserve(size);
        for (size_t i = 0; i < size; ++i) {
            result.push_back(vector1[i] ^ vector2[i]);
        }
    }

};
