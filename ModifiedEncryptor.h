// cryptography.h - Taken from cryptopp/default.h, modified and placed in 
// the kryptan project by Alexander Nilsson.
// default.h - written and placed in the public domain by Wei Dai
#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>

NAMESPACE_BEGIN(CryptoPP)

typedef AES Modified_BlockCipher;
typedef SHA ModifiedHashModule;
typedef HMAC<ModifiedHashModule> ModifiedMAC;

//! Password-Based Encryptor using AES
class ModifiedEncryptor : public ProxyFilter
{
public:
    ModifiedEncryptor(const char *passphrase, BufferedTransformation *attachment = NULL);
    ModifiedEncryptor(const byte *passphrase, size_t passphraseLength, BufferedTransformation *attachment = NULL);

protected:
    void FirstPut(const byte *);
    void LastPut(const byte *inString, size_t length);

private:
    SecByteBlock m_passphrase;
    CBC_Mode<Modified_BlockCipher>::Encryption m_cipher;
};

//! Password-Based Decryptor using AES
class ModifiedDecryptor : public ProxyFilter
{
public:
    ModifiedDecryptor(const char *passphrase, BufferedTransformation *attachment = NULL, bool throwException = true);
    ModifiedDecryptor(const byte *passphrase, size_t passphraseLength, BufferedTransformation *attachment = NULL, bool throwException = true);

    class Err : public Exception
    {
    public:
        Err(const std::string &s)
            : Exception(DATA_INTEGRITY_CHECK_FAILED, s) {}
    };
    class KeyBadErr : public Err { public: KeyBadErr() : Err("DefaultDecryptor: cannot decrypt message with this passphrase") {} };

    enum State { WAITING_FOR_KEYCHECK, KEY_GOOD, KEY_BAD };
    State CurrentState() const { return m_state; }

protected:
    void FirstPut(const byte *inString);
    void LastPut(const byte *inString, size_t length);

    State m_state;

private:
    void CheckKey(const byte *salt, const byte *keyCheck);

    SecByteBlock m_passphrase;
    CBC_Mode<Modified_BlockCipher>::Decryption m_cipher;
    member_ptr<FilterWithBufferedInput> m_decryptor;
    bool m_throwException;
};

//! Password-Based Encryptor using AES and HMAC/SHA-1
class ModifiedEncryptorWithMAC : public ProxyFilter
{
public:
    ModifiedEncryptorWithMAC(const char *passphrase, BufferedTransformation *attachment = NULL);
    ModifiedEncryptorWithMAC(const byte *passphrase, size_t passphraseLength, BufferedTransformation *attachment = NULL);

protected:
    void FirstPut(const byte *) {}
    void LastPut(const byte *inString, size_t length);

private:
    member_ptr<ModifiedMAC> m_mac;
};

//! Password-Based Decryptor using AES and HMAC/SHA-1
class ModifiedDecryptorWithMAC : public ProxyFilter
{
public:
    class MACBadErr : public ModifiedDecryptor::Err { public: MACBadErr() : ModifiedDecryptor::Err("DefaultDecryptorWithMAC: MAC check failed") {} };

    ModifiedDecryptorWithMAC(const char *passphrase, BufferedTransformation *attachment = NULL, bool throwException = true);
    ModifiedDecryptorWithMAC(const byte *passphrase, size_t passphraseLength, BufferedTransformation *attachment = NULL, bool throwException = true);

    ModifiedDecryptor::State CurrentState() const;
    bool CheckLastMAC() const;

protected:
    void FirstPut(const byte *) {}
    void LastPut(const byte *inString, size_t length);

private:
    member_ptr<ModifiedMAC> m_mac;
    HashVerifier *m_hashVerifier;
    bool m_throwException;
};

NAMESPACE_END

#endif
