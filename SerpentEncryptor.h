#ifndef TRIPLEENCRYPTOR_H
#define TRIPLEENCRYPTOR_H

#include "SecureString.h"

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

namespace Kryptan{
    namespace Core{
        namespace Internal{

            //the implementation is private
            class EncryptionKey{};

            //Encrypts-Decrypts strings with AES-Twofish-Serpent with a passphrase derived key.
            //Content is verified with HMAC using SHA3-512.
            class SerpentEncryptor
            {
            public:
                //This is the most CPUintensive part of the encryption/decryption process
                //thus is has been extracted so that the result can be cached.
                static EncryptionKey* generateKeyFromPassphraseRandomSalt(SecureString passphrase, int mashIterations = 0);
                static EncryptionKey* generateKeyFromPassphraseFixedSalt(SecureString passphrase, std::string filecontents);

                //Returns a encrypted, null terminated and HEX-encoded char array
                static std::string Encrypt(SecureString toEncrypt, EncryptionKey* key);

                //Returns a decrypted SecureString, and takes a null terminated hex encoded char array as input
                static SecureString Decrypt(std::string filecontents, EncryptionKey* key);

            private:
                SerpentEncryptor();
                SerpentEncryptor(const SerpentEncryptor& obj);
                ~SerpentEncryptor();

            };

        }
    }
}

#endif