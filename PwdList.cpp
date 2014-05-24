#include "PwdList.h"
#include <stdexcept>
#include <string.h>
#include "Exceptions.h"

using namespace Kryptan::Core;
using namespace std;

#ifdef _WIN32
#include <windows.h>

const char* strcasestr(char* haystack, char* needle)
{
    int i;
    int matchamt = 0;

    for(i=0;i<haystack[i];i++)
    {
        if (tolower(haystack[i]) != tolower(needle[matchamt]))
        {
            matchamt = 0;
        }
        if (tolower(haystack[i]) == tolower(needle[matchamt]))
        {
            matchamt++;
            if (needle[matchamt] == 0) return (char *)1;
        }
}

    return 0;
}

#else
//unix
#define _strcmpi strcasecmp
#endif

bool myPwdCompare(Pwd* a, Pwd* b)
{
    SecureString aSstr = a->GetDescription();
    const char* aStr = aSstr.getUnsecureString();
    SecureString bSstr = b->GetDescription();
    const char* bStr = bSstr.getUnsecureString();
    bool res = _strcmpi(aStr, bStr) < 0;
    aSstr.UnsecuredStringFinished();
    bSstr.UnsecuredStringFinished();
    return res;
}

bool myLabelcompare(SecureString a, SecureString b)
{
    const char* aStr = a.getUnsecureString();
    const char* bStr = b.getUnsecureString();
    bool res = _strcmpi(aStr, bStr) < 0;
    a.UnsecuredStringFinished();
    b.UnsecuredStringFinished();
    return res;
}

PwdList::PwdList(void)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
}


PwdList::~PwdList(void)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    for (auto it = pwds.begin(); it != pwds.end(); it++)
    {
        delete (*it);
    }
}

PwdList::PwdList(const PwdList& obj)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    throw std::logic_error("Not implemented");
}

PwdList::PwdVector PwdList::All()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    pwds.sort(myPwdCompare);
    return PwdVector(pwds.begin(), pwds.end());
}

PwdList::PwdVector PwdList::Filter(const SecureString& pattern)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    return Filter(pattern, PwdLabelVector());
}

PwdList::PwdVector PwdList::Filter(const PwdLabelVector& labels)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    return Filter(SecureString(), labels);
}

PwdList::PwdVector PwdList::Filter(const SecureString& pattern, const PwdLabelVector& labels)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    PwdVector filtered;
    if (pattern.length() > 0)
    {
        SecureString patternCpy = pattern;
        char* strPtrn = (char*)patternCpy.getUnsecureString();

        for (auto it = pwds.begin(); it != pwds.end(); it++)
        {
            SecureString description = (*it)->GetDescription();
            if (strcasestr((char*)description.getUnsecureString(), strPtrn) != NULL)
            {
                filtered.push_back((*it));
            }
            description.UnsecuredStringFinished();
        }

        patternCpy.UnsecuredStringFinished();
    }
    else {
        filtered = PwdVector(pwds.begin(), pwds.end());
    }

    if (labels.size() > 0)
    {
        for (auto iLabel = labels.begin(); iLabel != labels.end(); iLabel++)
        {
            PwdVector passed;
            for (auto iPwd = filtered.begin(); iPwd != filtered.end(); iPwd++)
            {
                if ((*iPwd)->HasLabel(*iLabel))
                {
                    passed.push_back(*iPwd);
                }
            }
            filtered = passed;
        }
    }

    pwds.sort(myPwdCompare);
    return filtered;
}


Pwd* PwdList::CreatePwd(const SecureString& desciption, const SecureString& password)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    return CreatePwd(desciption, SecureString(), password);
}

Pwd* PwdList::CreatePwd(const SecureString& desciption, const SecureString& username, const SecureString& password)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    //check if pwd is unique
    for (auto it = pwds.begin(); it != pwds.end(); it++)
    {
        if ((*it)->GetDescription().equals(desciption))
            throw KryptanDuplicatePwdException("A password already exist with that name!");
    }

    Pwd* pwd = new Pwd(this);
    pwd->SetDescription(desciption);
    pwd->SetUsername(username);
    pwd->SetPassword(password);

    pwds.push_back(pwd);

    return pwd;
}

Pwd* PwdList::CreatePwd(const SecureString& desciption, const SecureString& username, const SecureString& password, time_t created, time_t modified)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    Pwd* pwd = CreatePwd(desciption, username, password);
    pwd->SetCTime(created);
    pwd->SetMTime(modified);
    return pwd;
}

void PwdList::DeletePwd(Pwd* pwd)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    auto sizeBefore = pwds.size();
    auto labels = pwd->GetLabels();
    for (auto label = labels.begin(); label != labels.end(); label++)
    {
        RemovePwdFromLabel(pwd, *label);
    }
    pwds.remove(pwd);
    delete pwd;
    if (pwds.size() < sizeBefore - 1)
        throw KryptanBaseException("DeletePwd removed more than one password, something probably went seriously wrong!");
}

PwdLabelVector PwdList::AllLabels()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    existingLabels.sort(myLabelcompare);
    return PwdLabelVector(existingLabels.begin(), existingLabels.end());
}

PwdLabelVector PwdList::FilterLabels(SecureString pattern)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    PwdLabelVector vector;
    const char* strPtrn = pattern.getUnsecureString();
    for (auto it = existingLabels.begin(); it != existingLabels.end(); it++)
    {
        if (strstr(strPtrn, (*it).getUnsecureString()) != NULL)
        {
            vector.push_back((*it));
        }
        (*it).UnsecuredStringFinished();
    }
    pattern.UnsecuredStringFinished();

    std::sort(vector.begin(), vector.end(), myLabelcompare);
    return vector;
}

int PwdList::CountPwds()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    return pwds.size();
}

int PwdList::CountPwds(const SecureString& label)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    int count = 0;
    for (auto it = pwds.begin(); it != pwds.end(); it++)
    {
        if ((*it)->HasLabel(label))
            count++;
    }
    return count++;
}


bool PwdList::AddPwdToLabel(Pwd* pwd, SecureString label)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    if (std::find(existingLabels.begin(), existingLabels.end(), label) == existingLabels.end())
    {
        existingLabels.push_back(label);
    }
    pwd->AddLabel(label);
    return false;
}

bool PwdList::AddPwdToLabelNoMTime(Pwd* pwd, SecureString label)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    if (std::find(existingLabels.begin(), existingLabels.end(), label) == existingLabels.end())
    {
        existingLabels.push_back(label);
    }
    pwd->AddLabelNoMTime(label);
    return false;
}

bool PwdList::RemovePwdFromLabel(Pwd* pwd, SecureString label)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    pwd->RemoveLabel(label);
    if (CountPwds(label) == 0)
    {
        existingLabels.remove(label);
    }
    return false;
}

bool PwdList::ValidateDescription(Pwd* pwd, const SecureString& newDescription)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    //check if pwd is unique
    for (auto it = pwds.begin(); it != pwds.end(); it++)
    {
        if ((*it) != pwd && (*it)->GetDescription().equals(newDescription))
            return false;
    }
    return true;
}

void PwdList::ImportPwd(Pwd* pwd)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_lock);
    if (pwd == NULL)
        return;

    Pwd* imported = CreatePwd(pwd->GetDescription(), pwd->GetUsername(), pwd->GetPassword(), pwd->GetTimeCreated(), pwd->GetTimeLastModified());
    auto label = pwd->GetLabels();

    for (auto it = label.begin(); it != label.end(); it++)
    {
        AddPwdToLabel(imported, *it);
    }
}