#include "PwdFile.h"
#include "SerpentEncryptor.h"
#include "ModifiedEncryptor.h"
#include "PwdFileWorker.h"
#include <cryptopp/hex.h>
#include <fstream>
#include <stdexcept>

using namespace Kryptan::Core;
using namespace std;
using namespace CryptoPP;


PwdFile::PwdFile(string filename)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    this->filename = filename;
    list = NULL;
    isOpen = false;
}


PwdFile::~PwdFile(void)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    PwdFileWorker::DeletePwdList(list);
}

PwdFile::PwdFile(const PwdFile& obj)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
}

void PwdFile::CreateNew()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    if (isOpen)
        throw logic_error("File is already open!");

    list = PwdFileWorker::ParseFileContents(SecureString("<passwords></passwords>"));

    isOpen = true;
}

PwdList* DecryptAndParse(SecureString masterkey, const char* encryptedBuffer, int encryptedBufferLength, bool useOldFormat)
{
    //destination
    SecureString decryptedString;

    //decrypt the contents
    try{
        Internal::EncryptionKey* key = Internal::SerpentEncryptor::generateKeyFromPassphraseFixedSalt(masterkey, encryptedBuffer);
        decryptedString = Internal::SerpentEncryptor::Decrypt(encryptedBuffer, key);

        PwdFileWorker::ConvertToLocalEncoding(decryptedString);
    }
    catch (KryptanDecryptMacBadException &eOrig)
    {
        //Let's try to be backwards compatible
        try{
            decryptedString = PwdFileWorker::Decrypt(encryptedBuffer, encryptedBufferLength, masterkey);
        }
        catch (KryptanDecryptWrongKeyException)
        {
            //no that didn't work either, so let's just report the original error and continue
            throw eOrig;
        }
    }

    if (!useOldFormat){
        //parse the contents
        return PwdFileWorker::ParseFileContents(decryptedString);
    }
    else{
        return PwdFileWorker::ParseFileContentsOldFormat(decryptedString);
    }
}

void PwdFile::OpenAndParse(SecureString masterkey, bool useOldFormat)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    char* encryptedBuffer = 0;
    int encryptedBufferLength;
    try{
        if (isOpen)
            throw logic_error("File is already open!");

        //open file and read it's content
        PwdFileWorker::ReadFile(filename, encryptedBufferLength, encryptedBuffer);

        list = DecryptAndParse(masterkey, encryptedBuffer, encryptedBufferLength, useOldFormat);

        //delete the encrypted buffer
        delete[] encryptedBuffer;
        encryptedBuffer = 0;

        isOpen = true;
    }
    catch (...)
    {
        delete[] encryptedBuffer;
        //just re-throw, we let the caller handle theese errors
        throw;
    }
}

void PwdFile::ReplaceContent(SecureString masterkey, std::string newContent)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    //delete current list
    PwdList* newList = DecryptAndParse(masterkey, newContent.data(), newContent.length(), false);
    PwdFileWorker::DeletePwdList(list);
    list = newList;
}

void PwdFile::Save(SecureString masterkey)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    if (!isOpen)
        throw logic_error("File must be opened before Save() can be called!");

    SecureString content = GetCurrentContent();

    PwdFileWorker::ConvertToStorageEncoding(content);

    Internal::EncryptionKey* key = Internal::SerpentEncryptor::generateKeyFromPassphraseRandomSalt(masterkey);
    std::string encrypted = Internal::SerpentEncryptor::Encrypt(content, key);

    PwdFileWorker::WriteFile(filename, encrypted.data(), encrypted.length());
}

std::string PwdFile::SaveToString(SecureString masterkey, int mashIterations)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    SecureString content = GetCurrentContent();

    PwdFileWorker::ConvertToStorageEncoding(content);

    Internal::EncryptionKey* key = Internal::SerpentEncryptor::generateKeyFromPassphraseRandomSalt(masterkey, mashIterations);
    return Internal::SerpentEncryptor::Encrypt(content, key);
}

SecureString PwdFile::GetCurrentContent()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    SecureString content(RootTagStart);

    auto pwds = list->All();
    for (auto pwd = pwds.begin(); pwd != pwds.end(); pwd++)
    {
        content.append(PwdTagStart);

        //description
        content.append(DescriptionTagStart);
        content.append(PwdFileWorker::EscapeTags((*pwd)->GetDescription()));
        content.append(DescriptionTagEnd);

        //username
        content.append(UsernameTagStart);
        content.append(PwdFileWorker::EscapeTags((*pwd)->GetUsername()));
        content.append(UsernameTagEnd);

        //password
        content.append(PasswordTagStart);
        content.append(PwdFileWorker::EscapeTags((*pwd)->GetPassword()));
        content.append(PasswordTagEnd);

        //Created time
        content.append(TimeCreatedTagStart);
        content.append(PwdFileWorker::TimeToString((*pwd)->GetTimeCreated()));
        content.append(TimeCreatedTagEnd);

        //Modified Time
        content.append(TimeModifiedTagStart);
        content.append(PwdFileWorker::TimeToString((*pwd)->GetTimeLastModified()));
        content.append(TimeModifiedTagEnd);

        //labels
        auto labels = (*pwd)->GetLabels();
        for (auto label = labels.begin(); label != labels.end(); label++)
        {
            content.append(LabelTagStart);
            content.append(PwdFileWorker::EscapeTags(*label));
            content.append(LabelTagEnd);
        }

        content.append(PwdTagEnd);
    }
    content.append(RootTagEnd);
    return content;
}

PwdList* PwdFile::GetPasswordList()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    if (!isOpen)
        throw logic_error("File must be opened before GetPasswordList() can be called!");
    return list;
}

string PwdFile::GetFilename()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    return filename;
}

bool PwdFile::IsOpen()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    return isOpen;
}

bool PwdFile::Exists()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    return PwdFileWorker::FileExists(filename);
}