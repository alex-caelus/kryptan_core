#include "PwdFile.h"
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
    this->filename = filename;
    list = NULL;
    isOpen = false;
}


PwdFile::~PwdFile(void)
{
    PwdFileWorker::DeletePwdList(list);
}

PwdFile::PwdFile(const PwdFile& obj)
{
}

void PwdFile::CreateNew()
{
    if(isOpen)
        throw logic_error("File is already open!");

    list = PwdFileWorker::ParseFileContents(SecureString("<passwords></passwords>"));

    isOpen = true;
}

void PwdFile::OpenAndParse(SecureString masterkey, bool useOldFormat)
{
    char* encryptedBuffer = 0;
    int encryptedBufferLength;
    try{
        if(isOpen)
            throw logic_error("File is already open!");

        //open file and read it's content
        PwdFileWorker::ReadFile(filename, encryptedBufferLength, encryptedBuffer);

        //decrypt the contents
        SecureString decryptedString = PwdFileWorker::Decrypt(encryptedBuffer, encryptedBufferLength, masterkey);
        
        //delete the encrypted buffer
        delete[] encryptedBuffer;
        encryptedBuffer = 0;

        if(!useOldFormat){
            //parse the contents
            list = PwdFileWorker::ParseFileContents(decryptedString);
        }
        else{
            list = PwdFileWorker::ParseFileContentsOldFormat(decryptedString);
        }

        isOpen = true;
    }
    catch(...)
    {
        delete[] encryptedBuffer;
        //just re-throw, we let the caller handle theese errors
        throw;
    }
}

void PwdFile::Save(SecureString masterkey)
{
    if(!isOpen)
        throw logic_error("File must be opened before Save() can be called!");

    SecureString content(RootTagStart);

    auto pwds = list->All();
    for(auto pwd = pwds.begin(); pwd != pwds.end(); pwd++)
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

        //labels
        auto labels = (*pwd)->GetLabels();
        for(auto label = labels.begin(); label != labels.end(); label++)
        {
            content.append(LabelTagStart);
            content.append(PwdFileWorker::EscapeTags(*label));
            content.append(LabelTagEnd);
        }
        
        content.append(PwdTagEnd);
    }
    content.append(RootTagEnd);

    int eLength;
    char* encrypted = PwdFileWorker::Encrypt(content, eLength, masterkey);

    PwdFileWorker::WriteFile(filename, encrypted, eLength);
}

PwdList* PwdFile::GetPasswordList()
{
    if(!isOpen)
        throw logic_error("File must be opened before GetPasswordList() can be called!");
    return list;
}

string PwdFile::GetFilename()
{
    return filename;
}

bool PwdFile::IsOpen()
{
    return isOpen;
}

bool PwdFile::Exists()
{
    return PwdFileWorker::FileExists(filename);
}