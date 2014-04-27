#include "PwdFileWorker.h"
#include "ModifiedEncryptor.h"
#include <cryptopp/hex.h>
#include <fstream>
#include <stdexcept>
#include <stack>          // std::stack
#include <deque>          // std::deque
#include <sstream>
#include <ctime>

using namespace Kryptan::Core;
using namespace std;
using namespace CryptoPP;

void PwdFileWorker::ReadFile(string filename, int& length, char*& buffer)
{
    std::ifstream is;
    try
    {
        buffer = 0;

        //open file
        is.open(filename, std::ios::in | std::ios::binary );

        if(!is){
            //file is not found or readable
            throw KryptanFileNotReadableException("File not found or not readable");
        }

        // get length of file:
        is.seekg (0, std::ios::end);
        length = (int)is.tellg();
        is.seekg (0, std::ios::beg);

        // allocate memory:
        buffer = new char [length+1];// the buffer is deallocated by Decrypt

        // read data as a block:
        is.read (buffer, length);
        is.close();

        //add '\0' at the end
        buffer[length] = '\0';

    }
    catch(KryptanFileNotReadableException)
    {
        delete[] buffer;
        //we re-throw to let the caller handle the error
        throw;
    }
    catch(std::exception &e)
    {
        delete[] buffer;
        throw KryptanFileNotReadableException(e.what());
    }
}

void PwdFileWorker::WriteFile(string filename, const char* content, int length)
{
    std::ofstream os;
    try
    {
        //open file
        os.open(filename, std::ios::out | std::ios::binary | std::ios::trunc );

        if(!os){
            //file is not found or readable
            throw KryptanFileNotWritableException("File could not be opened or created for writing");
        }
        
        // read data as a block:
        os.write(content, length);
        os.close();
    }
    catch(std::exception& e)
    {
        //we re-throw to let the caller handle the error
        throw KryptanFileNotWritableException(e.what());
    }
}

bool PwdFileWorker::FileExists(string filename)
{
    ifstream ifile(filename, ifstream::in);
    return ifile.good();
}

PwdList* PwdFileWorker::ParseFileContents(SecureString content)
{
    PwdList* target = new PwdList();

    char* currTag = (char*)content.getUnsecureString();
    int currTagLength = GetTagLength(currTag);
    enum STATES {NOTSET, ROOT, PASSWORD};
    
    STATES currState = NOTSET;
    SecureString currDescription;
    SecureString currUsername;
    SecureString currPassword;
	time_t currMtime;
	time_t currCtime;
    PwdLabelVector currLabels;

	//for backwards compability
	time_t dummyCreationDate = time(0);
	int passwordsWithoutCreationDates = 0;
    
    try{
        do{
            switch(currState)
            {
            case NOTSET:
                if(strncmp(currTag, RootTagStart, currTagLength) == 0){
                    currState = ROOT;
                }
                else if(strncmp(currTag, "2.0\n__SUB-TREE__", 3) == 0) {
                    throw KryptanFileVersionException("Password file is using an old format");
                }
                else {
                    throw KryptanFileContentException("Password file is corrupt");
                }
                break;
            case ROOT:
                if(strncmp(currTag, PwdTagStart, currTagLength) == 0){
                    currDescription.assign("", 0);
                    currUsername.assign("", 0);
                    currPassword.assign("", 0);
					currCtime = 0;
					currMtime = 0;
                    currLabels.clear();
                    currState = PASSWORD;
                }
                else if(strncmp(currTag, RootTagEnd, currTagLength) == 0){
                    currState = NOTSET;
                    //we are done :)
                }
                else{
                    throw KryptanFileContentException("Password file is corrupt");
                }
                break;
            case PASSWORD:
                if(strncmp(currTag, DescriptionTagStart, currTagLength) == 0){
                    char* contentBegin = currTag + currTagLength;
                    char* contentEnd = GetNextTagStart(contentBegin);
                    int contentLength = contentEnd - contentBegin;
                    int endLength = GetTagLength(contentEnd);
                    if(strncmp(contentEnd, DescriptionTagEnd, endLength) == 0)
                    {
                        currDescription.assign(UnescapeTags(contentBegin, contentLength));
                    }
                    else{
                        throw KryptanFileContentException("Password file is corrupt");
                    }
                    currTag = contentEnd;
                }
                else if(strncmp(currTag, UsernameTagStart, currTagLength) == 0){
                    char* contentBegin = currTag + currTagLength;
                    char* contentEnd = GetNextTagStart(contentBegin);
                    int contentLength = contentEnd - contentBegin;
                    int endLength = GetTagLength(contentEnd);
                    if(strncmp(contentEnd, UsernameTagEnd, endLength) == 0)
                    {
                        currUsername.assign(UnescapeTags(contentBegin, contentLength));
                    }
                    else{
                        throw KryptanFileContentException("Password file is corrupt");
                    }
                    currTag = contentEnd;
                }
                else if(strncmp(currTag, PasswordTagStart, currTagLength) == 0){
                    char* contentBegin = currTag + currTagLength;
                    char* contentEnd = GetNextTagStart(contentBegin);
                    int contentLength = contentEnd - contentBegin;
                    int endLength = GetTagLength(contentEnd);
                    if(strncmp(contentEnd, PasswordTagEnd, endLength) == 0)
                    {
                        currPassword.assign(UnescapeTags(contentBegin, contentLength));
                    }
                    else{
                        throw KryptanFileContentException("Password file is corrupt");
                    }
                    currTag = contentEnd;
				}
				else if (strncmp(currTag, TimeCreatedTagStart, currTagLength) == 0){
					char* contentBegin = currTag + currTagLength;
					char* contentEnd = GetNextTagStart(contentBegin);
					int contentLength = contentEnd - contentBegin;
					int endLength = GetTagLength(contentEnd);
					if (strncmp(contentEnd, TimeCreatedTagEnd, endLength) == 0)
					{
						currCtime = stringToTime(contentBegin, contentLength);
					}
					else{
						throw KryptanFileContentException("Password file is corrupt");
					}
					currTag = contentEnd;
				}
				else if (strncmp(currTag, TimeModifiedTagStart, currTagLength) == 0){
					char* contentBegin = currTag + currTagLength;
					char* contentEnd = GetNextTagStart(contentBegin);
					int contentLength = contentEnd - contentBegin;
					int endLength = GetTagLength(contentEnd);
					if (strncmp(contentEnd, TimeModifiedTagEnd, endLength) == 0)
					{
						currMtime = stringToTime(contentBegin, contentLength);
					}
					else{
						throw KryptanFileContentException("Password file is corrupt");
					}
					currTag = contentEnd;
				}
                else if(strncmp(currTag, LabelTagStart, currTagLength) == 0){
                    char* contentBegin = currTag + currTagLength;
                    char* contentEnd = GetNextTagStart(contentBegin);
                    int contentLength = contentEnd - contentBegin;
                    int endLength = GetTagLength(contentEnd);
                    if(strncmp(contentEnd, LabelTagEnd, endLength) == 0)
                    {
                        currLabels.push_back(UnescapeTags(contentBegin, contentLength));
                    }
                    else{
                        throw KryptanFileContentException("Password file is corrupt");
                    }
                    currTag = contentEnd;
                }
                else if(strncmp(currTag, PwdTagEnd, currTagLength) == 0){
                    //validate what information we have
					if (currCtime == 0)
					{
						//create dummy creation date
						currCtime = dummyCreationDate - (passwordsWithoutCreationDates++);
					}
					if (currMtime == 0)
					{
						//create dummy modification date
						currMtime = currCtime;
					}

					//and save it
					Pwd* p = target->CreatePwd(currDescription, currUsername, currPassword, currCtime, currMtime);

                    for(PwdLabelVector::iterator it = currLabels.begin(); it != currLabels.end(); it++)
                    {
						target->AddPwdToLabelNoMTime(p, *it);
                    }

                    //change state
                    currState = ROOT;
                }
                else{
                    throw KryptanFileContentException("Password file is corrupt");
                }
                break;
            }
        }while((currTag = GetNextTagStart(currTag+1)) != NULL && (currTagLength = GetTagLength(currTag)) != 0);
    }
    catch(KryptanFileVersionException)
    {
        content.UnsecuredStringFinished();
        delete target;
        target = NULL;
        //rethrow;
        throw;
    }
    catch(std::exception &e)
    {
        content.UnsecuredStringFinished();
        delete target;
        target = NULL;
        throw KryptanFileContentException(e.what());
    }
    content.UnsecuredStringFinished();
    return target;
}

char* PwdFileWorker::GetNextTagStart(const char* pos)
{
    char* p = (char*)pos;
    for(; *p != '<' && *p != '\0'; p++){};
    return *p == '\0' ? NULL : p;
}

int PwdFileWorker::GetTagLength(const char* tagStart)
{
    char* p = (char*)tagStart;
    for(; *p != '>' && *p != '\0'; p++){}
    return p - tagStart + 1;
}

SecureString PwdFileWorker::EscapeTags(const SecureString& str)
{
    //we add a extra buffer length of 20 as a qualified 
    //guess, it doesn't realy matter since
    //SecureString is dynamic
    int l = str.length();
    SecureString copy(l + 20);

    for(int i=0; i < l; i++)
    {
        char c = str.at(i);
        if(c == '<')
        {
            const char* lt = "&lt;";
            copy.append(lt);
        }
        else if(c == '>')
        {
            const char* gt = "&gt;";
            copy.append(gt);
        }
        else if(c == '&')
        {
            const char* amp = "&amp;";
            copy.append(amp);
        }
        else
        {
            copy.append(&c, 1, false);		
        }
    }

    return copy;
}

SecureString PwdFileWorker::UnescapeTags(const char* str, int l)
{
    const char* lt = "<";
    const char* gt = ">";
    const char* amp = "&";
    
    SecureString copy(l);

    for(int i=0; i < l; i++)
    {
        char c = str[i];
        if(c == '&')
        {
            if(l - i >= 3)
            {
                //&lt;
                if(str[i+1] == 'l' && str[i+2] == 't' && str[i+3] == ';')
                {
                    copy.append(lt);
                    i += 3;
                    continue;
                }
                //&gt;
                else if(str[i+1] == 'g' && str[i+2] == 't' && str[i+3] == ';')
                {
                    copy.append(gt);
                    i += 3;
                    continue;
                }
            }
            if(l - i >= 4)
            {
                //&amp;
                if(str[i+1] == 'a' && str[i+2] == 'm' && str[i+3] == 'p' && str[i+4] == ';')
                {
                    copy.append(amp);
                    i += 4;
                    continue;
                }
            }
        }
        copy.append(&c, 1, false);
    }

    return copy;
}

time_t PwdFileWorker::stringToTime(char* start, int length)
{
	time_t t;
	std::stringstream str(std::string(start, length));
	str >> t;
	if (!str)
	{
		throw KryptanFileContentException("Password file is corrupt!");
	}
	return t;
}

SecureString PwdFileWorker::TimeToString(time_t time)
{
	string t;
	std::ostringstream str;
	str << time;
	//no need to securely delete this, it is not information that needs protecting
	return SecureString(str.str().c_str());
}

char* PwdFileWorker::Encrypt(SecureString data, int& encryptedLength, SecureString masterkey) {
    try {
        ModifiedEncryptorWithMAC encryptor(masterkey.getUnsecureString(), new HexEncoder());
        encryptor.Put((byte*) data.getUnsecureString(), data.length());
        encryptor.MessageEnd();

        encryptedLength = (int) encryptor.MaxRetrievable();
        char* newBuff = new char[encryptedLength + 1];
        encryptor.Get((byte*) newBuff, encryptedLength);
        newBuff[encryptedLength] = 0;
        masterkey.UnsecuredStringFinished();
        data.UnsecuredStringFinished();
        return newBuff;
    } catch (Exception const& e) {
        data.UnsecuredStringFinished();
        masterkey.UnsecuredStringFinished();
        throw runtime_error((char*) e.GetWhat().c_str());
        return NULL;
    }
}

SecureString PwdFileWorker::Decrypt(const char* encryptedBuffer, int encryptedBufferLength, SecureString masterkey)
{
    char* unsafeDecrypt = 0;
    int outputLength;

    if (masterkey.length() == 0) {
        throw runtime_error("Master key is zero in length");
    }

    try {
        ModifiedDecryptorWithMAC* p = new ModifiedDecryptorWithMAC(masterkey.getUnsecureString());
        HexDecoder decryptor(p);
        decryptor.Put((byte*) encryptedBuffer, encryptedBufferLength);
        decryptor.MessageEnd();

        outputLength = (int)decryptor.MaxRetrievable();
        unsafeDecrypt = new char[outputLength + 1];
        decryptor.Get((byte*) unsafeDecrypt, outputLength);
        unsafeDecrypt[outputLength] = 0;

        //delete
        masterkey.UnsecuredStringFinished();
        return SecureString(unsafeDecrypt); //This also deletes 'unsafeDecrypt' securely
    } 
    catch (ModifiedDecryptor::KeyBadErr) 
    {
        masterkey.UnsecuredStringFinished(); //We need to use this again
        delete[] unsafeDecrypt;

        throw KryptanDecryptWrongKeyException("Wrong master key!");
    } 
    catch (ModifiedDecryptorWithMAC::MACBadErr) 
    {
        masterkey.UnsecuredStringFinished(); //Secure the master key
        delete[] unsafeDecrypt;

        throw KryptanDecryptException("Filecontent is corrupt");
    } 
    catch (std::exception &e) 
    {
        masterkey.UnsecuredStringFinished(); //Secure the master key
        delete[] unsafeDecrypt;

        //rethrow
        throw KryptanDecryptException(e.what());
    }
}

void PwdFileWorker::DeletePwdList(PwdList* list)
{
    delete list;
}

void CreatePassword(PwdList* list, SecureString& desc, SecureString& user, SecureString& pass, deque<SecureString>& labels)
{
    bool success = false;
    Pwd* pwd;
    do{
        try{
            pwd = list->CreatePwd(desc, user, pass);
            success = pwd != NULL;
        }catch(KryptanDuplicatePwdException)
        {
            desc.append("(duplicate)");
            success = false;
        }
    }while(!success);
    //add labels
    for(auto it=labels.begin(); it != labels.end(); it++)
    {
        list->AddPwdToLabel(pwd, *it);
    }
}

PwdList*  PwdFileWorker::ParseFileContentsOldFormat(SecureString filecontent){
    #define PASSWORD_FILE_VERSION_NUMBER "2.0"
    #define TREESTART "__SUB-TREE__"
    #define TREEEND "__END-SUB-TREE__"
    #define PASSWORDSTART "__PASSWORD-ENTRY__"
    #define PASSWORDEND "__END-PASSWORD-ENTRY__"
    #define EMPTYLINE "__EMPTY__"

    //Define the parsestates
    enum {
        GET_VERSION,
        GET_NEXTENTRY,
        GET_TREENAME,
        GET_DESCRIPTION,
        GET_PASSWORD,
        GET_USERNAME
    } state = GET_VERSION;

    const char* currentLine;

    deque<SecureString> currentLabels;
    SecureString currentDescription;
    SecureString currentUsername;
    SecureString currentPassword;

    //Create a new root
    PwdList* list = new PwdList();

    bool keepParsing = true;
    //Parse the file
    while(keepParsing){
        //get next line
        currentLine = filecontent.getUnsecureNextline();

        switch(state){
            case GET_VERSION:
                if( strcmp(currentLine, PASSWORD_FILE_VERSION_NUMBER) != 0){
                    throw KryptanFileContentException("Password version mismatch!");
                }
                state = GET_NEXTENTRY;
                break;
            case GET_NEXTENTRY:
                //Are we done?
                if(strlen(currentLine) == 0){
                    keepParsing = false;
                }
                if( strcmp(currentLine, TREESTART) == 0){
                    state = GET_TREENAME;
                }
                if( strcmp(currentLine, TREEEND) == 0){
                    currentLabels.pop_back();
                }
                if( strcmp(currentLine, PASSWORDSTART) == 0){
                    state = GET_DESCRIPTION;
                    currentDescription.assign("");
                    currentUsername.assign("");
                    currentPassword.assign("");
                }
                if( strcmp(currentLine, PASSWORDEND) == 0){
                    //we have what we need to create a new password, let's do it.
                    CreatePassword(list, currentDescription, currentUsername, currentPassword, currentLabels);
                }
                break;
            case GET_TREENAME:
                {
                    currentLabels.push_back(SecureString(currentLine));
                    state = GET_NEXTENTRY;
                }
                break;
            case GET_DESCRIPTION:
                {
                    currentDescription.assign(currentLine);
                    state = GET_PASSWORD;
                }
                break;
            case GET_PASSWORD:
                {
                    currentPassword.assign(currentLine);
                    state = GET_USERNAME;
                }
                break;
            case GET_USERNAME:
                if(strcmp(currentLine, PASSWORDEND) != 0){
                    currentUsername.assign(currentLine);
                }
                else
                {
                    CreatePassword(list, currentDescription, currentUsername, currentPassword, currentLabels);
                }
                state = GET_NEXTENTRY;
                break;
        }

        //Delete the line, and get ready to read the next line
        filecontent.UnsecuredStringFinished();
    }

    return list;
}