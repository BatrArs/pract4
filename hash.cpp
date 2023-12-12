#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <iostream>
#include <string>

int main() {
    std::string filename = "file.txt";
    std::string digest;

    CryptoPP::SHA1 hash;
    CryptoPP::FileSource(filename.c_str(), true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(digest))));

    std::cout << "Hash: " << digest << std::endl;

    return 0;
}
