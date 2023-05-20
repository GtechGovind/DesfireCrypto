#include <iostream>
#include "../include/desfire_crypto/DesfireCrypto.h"

int main() {

    DesfireCrypto desfireCrypto;

    vector<unsigned char> key = {0x32, 0x01, 0x9B, 0xE4, 0xBC, 0x09, 0xA5, 0x20, 0x7A, 0xC7, 0xC6, 0x38, 0x65, 0xC2, 0x02, 0xA4, };
    vector<unsigned char> iv = vector<unsigned char>(16, 0x00);
    vector<unsigned char> message = {0x6C, 0x00};

    desfireCrypto.initCMAC(key, iv);
    desfireCrypto.generateSubkeys();

    cout << "DesfireCrypto: ";
    for (auto &i : desfireCrypto.getCMAC(message)) {
        cout << hex << uppercase << (int) i << " ";
    }

}
