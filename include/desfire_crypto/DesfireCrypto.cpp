#include "DesfireCrypto.h"

void DesfireCrypto::initCMAC(const vector<uint8_t>& _key, const vector<uint8_t>& _iv) {
    aes = AES(AESKeyLength::AES_128);
    key = _key;
    iv = _iv;
}

void DesfireCrypto::generateSubkeys() {

    vector<uint8_t> zero(16, 0x00);
    vector<unsigned char> key0 = encryptAes(zero, key, zero);

    leftShift(key0, key1);
    if (key0[0] & 0x80) key1[key1.size() - 1] ^= 0x87U;

    leftShift(key1, key2);
    if (key1[0] & 0x80) key2[key2.size() - 1] ^= 0x87U;

    vecPrint("key0", key0);
    vecPrint("key1", key1);
    vecPrint("key2", key2);

}

vector<uint8_t> DesfireCrypto::getCMAC(const vector<uint8_t>& data) {

    const int AES_BLOCK_SIZE = 16;
    bool isPaddingRequired = (data.size() % AES_BLOCK_SIZE != 0);
    int numberOfBlocks = isPaddingRequired ? data.size() / AES_BLOCK_SIZE + 1 : data.size() / AES_BLOCK_SIZE;

    vector<uint8_t> cmac(AES_BLOCK_SIZE / 2, 0x00);
    vector<vector<uint8_t>> blocks;

    for (int i = 0; i < numberOfBlocks; ++i) {
        int start = i * AES_BLOCK_SIZE;
        int end = min(start + AES_BLOCK_SIZE, static_cast<int>(data.size()));
        vector<uint8_t> block(data.begin() + start, data.begin() + end);
        blocks.push_back(block);
    }

    if (isPaddingRequired) {
        vector<uint8_t>& lastBlock = blocks.back();
        if (lastBlock.size() < AES_BLOCK_SIZE) {
            lastBlock.push_back(0x80);
            lastBlock.resize(AES_BLOCK_SIZE, 0x00);
        }
        xorVec(lastBlock, key2, lastBlock);
    } else {
        xorVec(blocks.back(), key1, blocks.back());
    }

    int offset = 0;
    vector<unsigned char> tempIv(AES_BLOCK_SIZE, 0x00);
    while (offset < numberOfBlocks) {
        vector<unsigned char> temp = blocks[offset];
        vector<unsigned char> xorTemp(AES_BLOCK_SIZE, 0x00);
        xorVec(iv, temp, xorTemp);
        temp = encryptAes(xorTemp, key, tempIv);
        iv = temp;
        offset += AES_BLOCK_SIZE;
    }

    cmac = {iv.begin(), iv.begin() + AES_BLOCK_SIZE / 2};

    return cmac;
}

void DesfireCrypto::setIv(const vector<uint8_t> &_iv) {
    iv = _iv;
}

vector<uint8_t> DesfireCrypto::encryptAes(vector<uint8_t> &data, const vector<uint8_t> &_key, const vector<uint8_t> &_iv) {
    return aes.EncryptCBC(data, _key, _iv);
}

vector<uint8_t> DesfireCrypto::decryptAes(vector<uint8_t> &data, const vector<uint8_t> &_key, const vector<uint8_t> &_iv) {
    return aes.DecryptCBC(data, _key, _iv);
}
