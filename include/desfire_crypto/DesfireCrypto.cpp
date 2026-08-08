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
}

vector<uint8_t> DesfireCrypto::getCMAC(const vector<uint8_t>& data) {

    constexpr size_t AES_BLOCK_SIZE = 16;
    const bool hasCompleteFinalBlock = !data.empty() && data.size() % AES_BLOCK_SIZE == 0;
    const size_t numberOfBlocks = max<size_t>(1, (data.size() + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE);

    vector<uint8_t> cmac(AES_BLOCK_SIZE / 2, 0x00);
    vector<vector<uint8_t>> blocks;
    blocks.reserve(numberOfBlocks);

    for (size_t i = 0; i < numberOfBlocks; ++i) {
        const size_t start = min(i * AES_BLOCK_SIZE, data.size());
        const size_t end = min(start + AES_BLOCK_SIZE, data.size());
        vector<uint8_t> block(data.begin() + start, data.begin() + end);
        blocks.push_back(block);
    }

    if (!hasCompleteFinalBlock) {
        vector<uint8_t>& lastBlock = blocks.back();
        lastBlock.push_back(0x80);
        lastBlock.resize(AES_BLOCK_SIZE, 0x00);
        xorVec(lastBlock, key2, lastBlock);
    } else {
        xorVec(blocks.back(), key1, blocks.back());
    }

    vector<unsigned char> tempIv(AES_BLOCK_SIZE, 0x00);
    for (size_t blockIndex = 0; blockIndex < numberOfBlocks; ++blockIndex) {
        vector<unsigned char> temp = blocks[blockIndex];
        vector<unsigned char> xorTemp(AES_BLOCK_SIZE, 0x00);
        xorVec(iv, temp, xorTemp);
        temp = encryptAes(xorTemp, key, tempIv);
        iv = temp;
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
