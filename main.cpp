#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

void encrypt(const std::string& inputFile, const std::string& outputFile, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv) {
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

    CryptoPP::FileSource(inputFile.c_str(), true,
        new CryptoPP::StreamTransformationFilter(cbcEncryption,
            new CryptoPP::FileSink(outputFile.c_str())
        )
    );
}

void decrypt(const std::string& inputFile, const std::string& outputFile, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv) {
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::MAX_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

    CryptoPP::FileSource(inputFile.c_str(), true,
        new CryptoPP::StreamTransformationFilter(cbcDecryption,
            new CryptoPP::FileSink(outputFile.c_str())
        )
    );
}

int main() {
    // Generate a random key
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key(CryptoPP::AES::MAX_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    // Initialization vector
    CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
    prng.GenerateBlock(iv, iv.size());

    // Encrypt and decrypt a file
    std::string inputFile = "input_file.txt";
    std::string encryptedFile = "encrypted.txt";
    std::string decryptedFile = "decrypted.txt";

    encrypt(inputFile, encryptedFile, key, iv);
    decrypt(encryptedFile, decryptedFile, key, iv);

    return 0;
}
