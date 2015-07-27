#include "SerpentEncryptor.h"
using Kryptan::Core::Internal::SerpentEncryptor;
using Kryptan::Core::Internal::EncryptionKey;
using Caelus::Utilities::SecureString;

#include "Exceptions.h"
using Kryptan::Core::KryptanBaseException;

//#define OS_RNG_AVAILABLE

#ifdef OS_RNG_AVAILABLE
# include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
#else
# include "cryptopp/randpool.h"
using CryptoPP::RandomPool;
#endif

#include "cryptopp/gcm.h"
using CryptoPP::GCM;

#include "cryptopp/serpent.h"
using CryptoPP::Serpent;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::BufferedTransformation;
using CryptoPP::AAD_CHANNEL;
using CryptoPP::DEFAULT_CHANNEL;

#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include "cryptopp/sha.h"
using CryptoPP::SHA512;
#include "cryptopp/sha3.h"
//using CryptoPP::SHA3_512;
#include "cryptopp/pwdbased.h"
using CryptoPP::PKCS5_PBKDF2_HMAC;

//while developing
//using namespace CryptoPP;

#define MAGIC_VALUE "KRYPTAN\n"

const int TAG_SIZE = 16; //bytes
const int IV_SIZE = 16; //bytes
typedef SHA512 KEY_CHECK_HASH_FUNCTION;
const int KEY_CHECK_LENGTH = KEY_CHECK_HASH_FUNCTION::DIGESTSIZE;
const int MIN_ITERATION_COUNT = 2 ^ 10;
const int TARGET_ITERATION_TIME = 2; //seconds
const int SALT_SIZE = 16; //bytes
typedef uint32_t iter_t;

RandomPool* getPrng()
{
#ifdef OS_RNG_AVAILABLE
    static AutoSeededRandomPool g_prng;
#else
    static RandomPool g_prng;
    static bool inited = false;
    if (!inited)
    {
  #if defined(_WIN32) && defined(WINAPI_FAMILY_APP)
        const int SEED_LEN = 32;
        auto iBuffer = Windows::Security::Cryptography::CryptographicBuffer::GenerateRandom(SEED_LEN);
        auto reader = Windows::Storage::Streams::DataReader::FromBuffer(iBuffer);
        std::vector<unsigned char> data(reader->UnconsumedBufferLength);
        if (!data.empty())
            reader->ReadBytes(
                ::Platform::ArrayReference<unsigned char>(
                    &data[0], data.size()
                )
            );
        g_prng.IncorporateEntropy(&data[0], SEED_LEN);
        inited = true;
  #else
    #error Requires cryptographically secure seed
  #endif
    }

#endif
    return &g_prng;
}

//
class EncryptionKeyImpl : public EncryptionKey
{
private:
    SecByteBlock xor1;
    SecByteBlock xor2;
    int keyLength;
    iter_t createdWithNumberOfIterations;
public:
    EncryptionKeyImpl(byte* kData, int kLength, byte* sData, int sLength, iter_t nIterations)
    {
        keyLength = kLength;
        xor1.Grow(kLength + sLength);
        xor2.Grow(kLength + sLength);
        createdWithNumberOfIterations = nIterations;

        //fill with random data
        getPrng()->GenerateBlock(xor1, kLength + sLength);

        //put key data into storage
        for (int i = 0; i < kLength; i++)
        {
            xor2[i] = kData[i] ^ xor1[i];
        }

        //put salt data into storage
        for (int i = 0; i < sLength; i++)
        {
            xor2[kLength + i] = sData[i] ^ xor1[kLength + i];
        }
    }

    SecByteBlock getDataCopy()
    {
        SecByteBlock data(keyLength);
        for (int i = 0; i < keyLength; i++)
        {
            data[i] = xor1[i] ^ xor2[i];
        }
        return data;
    }

    SecByteBlock getSaltCopy()
    {
        int saltLength = xor1.size() - keyLength;
        SecByteBlock data(saltLength);
        for (int i = 0; i < saltLength; i++)
        {
            data[i] = xor1[keyLength + i] ^ xor2[keyLength + i];
        }
        return data;
    }

    iter_t getNumberOfIterations()
    {
        return createdWithNumberOfIterations;
    }

    ~EncryptionKeyImpl()
    {
        //clean xor1 and xor2
        xor1.CleanNew(0);
        xor2.CleanNew(0);
    }
};

SerpentEncryptor::SerpentEncryptor()
{
};

SerpentEncryptor::~SerpentEncryptor()
{
};

EncryptionKeyImpl* generateKeyFromPassphrase_p(SecureString passphrase, SecByteBlock salt, iter_t iterations = 0)
{

    SecByteBlock derived_key(Serpent::DEFAULT_KEYLENGTH);

    double target_iteration_time = TARGET_ITERATION_TIME;
    iter_t iteration_count = MIN_ITERATION_COUNT;

    if (iterations > 0)
    {
        target_iteration_time = 0;
        iteration_count = iterations;
    }

    PKCS5_PBKDF2_HMAC<SHA512> pbkdf2;
    iter_t actualIterationCount = pbkdf2.DeriveKey(
        derived_key,
        derived_key.size(),
        0,
        reinterpret_cast<const byte *>(passphrase.getUnsecureString()),
        passphrase.length(),
        salt,
        salt.size(),
        iteration_count,
        target_iteration_time
        );

    return new EncryptionKeyImpl(derived_key, derived_key.size(), salt, salt.size(), actualIterationCount);
}

EncryptionKey* SerpentEncryptor::generateKeyFromPassphraseRandomSalt(SecureString passphrase, int mashIterations)
{
    SecByteBlock salt(SALT_SIZE);

    //generate salt
    getPrng()->GenerateBlock(salt, salt.size());

    return generateKeyFromPassphrase_p(passphrase, salt, mashIterations);
}

EncryptionKey* SerpentEncryptor::generateKeyFromPassphraseFixedSalt(SecureString passphrase, std::string filecontents)
{
    //DATA FORMAT
    //|            plaintext           |             encrypted            |  plain |    <-- confidentiality level
    //|-iter count-|-pwd salt--|--iv---|---------------data---------------|---mac--|    <-- data organization
    //|	   iter_t  | SALT_SIZE |IV_SIZE|          unknown length          |TAG_SIZE|    <-- data sizes


    if (filecontents.substr(0, sizeof(MAGIC_VALUE)-1) != MAGIC_VALUE)
    {
        // no magic value, then the string does not follow the format specified in this source file
        throw KryptanDecryptMacBadException("Bad format");
    }

    int offset = 0;

    std::string decoded;
    StringSource source(filecontents.substr(sizeof(MAGIC_VALUE)-1), true, new Base64Decoder(new StringSink(decoded)));

    //get password itereation count
    iter_t iteration_count = *reinterpret_cast<const iter_t*>(decoded.data());
    offset += sizeof(iter_t);
    //get password salt
    SecByteBlock pwdSalt(reinterpret_cast<const byte*>(decoded.substr(offset, SALT_SIZE).data()), SALT_SIZE);

    assert(pwdSalt.size() == (unsigned int)SALT_SIZE);

    return generateKeyFromPassphrase_p(passphrase, pwdSalt, iteration_count);
}



/*
* Time for encryption
* We use GCM mode with iv as ADATA (authenticated but not encrypted)
* PDATA is ofcourse 'data' and is both encrypted and authenticated
*/
std::string SerpentEncryptor::Encrypt(SecureString data, EncryptionKey* key)
{
    try
    {
        //get keydata
        EncryptionKeyImpl* keyImpl = static_cast<EncryptionKeyImpl*>(key);
        SecByteBlock keyData = keyImpl->getDataCopy();
        SecByteBlock keySaltData = keyImpl->getSaltCopy();
        iter_t iterations = keyImpl->getNumberOfIterations();

        //generate iv
        SecByteBlock iv(IV_SIZE);
        getPrng()->GenerateBlock(iv, iv.size());

        //put result here
        std::string encrypted(MAGIC_VALUE);

        //create keycheck block
        SecByteBlock keycheckShouldbe(KEY_CHECK_LENGTH);
        KEY_CHECK_HASH_FUNCTION hasher;
        hasher.Update(keyData, keyData.size());
        hasher.Final(keycheckShouldbe);

        GCM< Serpent >::Encryption e;
        e.SetKeyWithIV(keyData, keyData.size(), iv, iv.size());

        // Not required for GCM mode (but required for CCM mode)
        // e.SpecifyDataLengths( adata.size(), pdata.size(), 0 );

        BufferedTransformation* destination = new Base64Encoder(new StringSink(encrypted));

        //put iv to the beginning of the destination
        destination->Put(reinterpret_cast<const byte*>(&iterations), sizeof(iter_t));
        destination->Put(keySaltData, keySaltData.size());
        destination->Put(iv, iv.size());

        //ef takes ownership of destination, no delete necessary
        AuthenticatedEncryptionFilter ef(e, destination, false, TAG_SIZE);

        // AuthenticatedEncryptionFilter::ChannelPut
        //  defines two channels: "" (empty) and "AAD"
        //   channel "" is encrypted and authenticated
        //   channel "AAD" is authenticated
        // NOTE: AAD is not put into destination, thats 
        // why we have already done that manually.
        ef.ChannelPut(AAD_CHANNEL, reinterpret_cast<const byte*>(&iterations), sizeof(iter_t), true);
        ef.ChannelPut(AAD_CHANNEL, keySaltData, keySaltData.size());
        ef.ChannelPut(AAD_CHANNEL, iv, iv.size());
        ef.ChannelMessageEnd(AAD_CHANNEL);

        // Authenticated data *must* be pushed before
        //  Confidential/Authenticated data. Otherwise
        //  we must catch the BadState exception
        ef.ChannelPut(DEFAULT_CHANNEL, keycheckShouldbe, keycheckShouldbe.size());
        ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)data.getUnsecureString(), data.length());
        ef.ChannelMessageEnd(DEFAULT_CHANNEL);

        //we're finished with the unsecure data, let's remove it
        data.UnsecuredStringFinished();

        //return to caller with encrypted and encoded data
        return encrypted;
    }
    catch (CryptoPP::BufferedTransformation::NoChannelSupport& e)
    {
        data.UnsecuredStringFinished();
        // The tag must go in to the default channel:
        //  "unknown: this object doesn't support multiple channels"
        // this should never happen
        throw KryptanEncryptException(std::string("Error while encrypting: ") + e.what());
    }
    catch (CryptoPP::AuthenticatedSymmetricCipher::BadState& e)
    {
        data.UnsecuredStringFinished();
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"

        //this should also never happen
        throw KryptanEncryptException(std::string("Error while encrypting: ") + e.what());
    }
    catch (CryptoPP::InvalidArgument& e)
    {
        data.UnsecuredStringFinished();
        //some arguments were invalid
        //this should ofcourse never happen
        throw KryptanEncryptException(std::string("Error while encrypting: ") + e.what());
    }
    catch (CryptoPP::Exception& e)
    {
        data.UnsecuredStringFinished();
        //unknown exception
        throw KryptanEncryptException(std::string("Error while encrypting: ") + e.what());
    }
}



SecureString SerpentEncryptor::Decrypt(std::string data, EncryptionKey* key)
{
    try
    {
        if (data.substr(0, sizeof(MAGIC_VALUE)-1) != MAGIC_VALUE)
        {
            // no magic value, then the string does not follow the format specified in this source file
            throw KryptanDecryptMacBadException("Bad format");
        }
        //source
        std::string decoded;
        StringSource source(data.substr(sizeof(MAGIC_VALUE)-1), true, new Base64Decoder(new StringSink(decoded)));

        //DATA FORMAT
        //|            plaintext           |             encrypted            |  plain |    <-- confidentiality level
        //|-iter count-|-pwd salt--|--iv---|---------------data---------------|---mac--|    <-- data organization
        //|	   iter_t  | SALT_SIZE |IV_SIZE|          unknown length          |TAG_SIZE|    <-- data sizes

        //pre-data exraction sanity check
        assert(data.length() > TAG_SIZE + IV_SIZE);

        int offset = sizeof(iter_t)+SALT_SIZE;
        //get iv
        SecByteBlock iv(reinterpret_cast<const byte*>(decoded.substr(offset, IV_SIZE).data()), IV_SIZE);
        offset += IV_SIZE;
        //get encrypted
        std::string encrypted = decoded.substr(offset, decoded.length() - offset - TAG_SIZE);
        //get mac
        std::string mac = decoded.substr(decoded.length() - TAG_SIZE);

        //post-data exraction sanity checks
        assert(iv.size() == (unsigned int)IV_SIZE);
        assert(encrypted.size() > 0);
        assert(mac.size() == (unsigned int)TAG_SIZE);

        //get keydata
        EncryptionKeyImpl* keyImpl = static_cast<EncryptionKeyImpl*>(key);
        SecByteBlock keyData = keyImpl->getDataCopy();
        iter_t iterations = keyImpl->getNumberOfIterations();
        SecByteBlock keySaltData = keyImpl->getSaltCopy();

        //Decryptor
        GCM<Serpent>::Decryption d;
        d.SetKeyWithIV(keyData, keyData.size(), iv, iv.size());

        // Object _will_ throw an exception
        //  during decryption\verification _if_
        //  verification fails.
        AuthenticatedDecryptionFilter df(d, NULL,
            AuthenticatedDecryptionFilter::MAC_AT_END |
            AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE);

        //the order of the follwing is important
        df.ChannelPut(AAD_CHANNEL, reinterpret_cast<const byte*>(&iterations), sizeof(iter_t), true);
        df.ChannelPut(AAD_CHANNEL, keySaltData, keySaltData.size());
        df.ChannelPut(AAD_CHANNEL, iv, iv.size());
        df.ChannelMessageEnd(AAD_CHANNEL);

        df.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const byte*>(encrypted.data()), encrypted.size());
        df.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const byte*>(mac.data()), mac.size());
        df.ChannelMessageEnd(DEFAULT_CHANNEL);

        //if we get this far the authentication is successfull :)

        df.SetRetrievalChannel(DEFAULT_CHANNEL);
        auto totaldecryptedsize = df.MaxRetrievable();

        if (totaldecryptedsize < (unsigned int)KEY_CHECK_LENGTH)
        {
            throw KryptanDecryptMacBadException("Error while decrypting: Cannot find keycheck data!");
        }

        //keycheck
        SecByteBlock keycheck(KEY_CHECK_LENGTH);
        SecByteBlock keycheckShouldbe(KEY_CHECK_LENGTH);
        df.Get(keycheck, keycheck.size());
        KEY_CHECK_HASH_FUNCTION hasher;
        hasher.Update(keyData, keyData.size());
        hasher.Final(keycheckShouldbe);

        if (!VerifyBufsEqual(keycheck, keycheckShouldbe, KEY_CHECK_LENGTH))
        {
            throw KryptanDecryptWrongKeyException("Incorrect key!");
        }

        auto datasize = totaldecryptedsize - KEY_CHECK_LENGTH;

        if (datasize <= 0)
            return SecureString();

        //get data
        byte* destination = new byte[(int)datasize + 1];
        df.Get(destination, (size_t)datasize);
        destination[datasize] = 0;//null terminate

        //imports the data securely and deletes the buffer
        SecureString decrypted((SecureString::ssarr) destination);

        return decrypted;
    }
    catch (CryptoPP::InvalidArgument& e)
    {
        //invalid argument somewhere
        //this should not happen
        throw KryptanDecryptException(e.what());
    }
    catch (CryptoPP::AuthenticatedSymmetricCipher::BadState& e)
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        throw KryptanDecryptException(e.what());
    }
    catch (CryptoPP::HashVerificationFilter::HashVerificationFailed)
    {
        throw KryptanDecryptMacBadException("Integrity check failed, password file is corrupt.");
    }
}
