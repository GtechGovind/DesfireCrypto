#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "desfire_crypto/DesfireCrypto.h"

namespace {

std::vector<uint8_t> fromHex(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

void expectCmac(const std::string& name, const std::string& messageHex, const std::string& expectedHex) {
    DesfireCrypto crypto;
    auto key = fromHex("2b7e151628aed2a6abf7158809cf4f3c");
    std::vector<uint8_t> iv(16, 0x00);
    const auto message = fromHex(messageHex);

    crypto.initCMAC(key, iv);
    crypto.generateSubkeys();
    const auto actual = crypto.getCMAC(message);
    const auto expected = fromHex(expectedHex);

    if (actual != expected) {
        std::cerr << name << " failed" << std::endl;
        std::exit(EXIT_FAILURE);
    }
}

}  // namespace

int main() {
    expectCmac("empty message", "", "bb1d6929e9593728");
    expectCmac(
        "one complete block",
        "6bc1bee22e409f96e93d7e117393172a",
        "070a16b46b4d4144"
    );
    expectCmac(
        "partial final block",
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411",
        "dfa66747de9ae630"
    );
    expectCmac(
        "four complete blocks",
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710",
        "51f0bebf7e3b9d92"
    );

    std::cout << "All AES-CMAC vectors passed" << std::endl;
    return EXIT_SUCCESS;
}
