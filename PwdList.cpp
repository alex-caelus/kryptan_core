#include "PwdList.h"
#include <stdexcept>
#include <string.h>
#include "Exceptions.h"

using namespace Kryptan::Core;
using namespace std;

#ifdef _WIN32
#include <boost/algorithm/string/find.hpp>

const char* strcasestr( char* haystack, char* needle )
{
   using namespace boost;
   iterator_range<char*> result = ifind_first( haystack, needle );
   if( result ) return result.begin();

   return NULL;
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
}


PwdList::~PwdList(void)
{
    for(auto it=pwds.begin(); it != pwds.end(); it++)
    {
        delete (*it);
    }
}

PwdList::PwdList(const PwdList& obj)
{
    throw std::logic_error("Not implemented");
}

PwdList::PwdVector PwdList::All()
{
    pwds.sort(myPwdCompare);
    return PwdVector(pwds.begin(), pwds.end());
}

PwdList::PwdVector PwdList::Filter(const SecureString& pattern)
{
    return Filter(pattern, PwdLabelVector());
}

PwdList::PwdVector PwdList::Filter(const PwdLabelVector& labels)
{
    return Filter(SecureString(), labels);
}

PwdList::PwdVector PwdList::Filter(const SecureString& pattern, const PwdLabelVector& labels)
{
    PwdVector filtered;
    if(pattern.length() > 0)
    {
        SecureString patternCpy = pattern;
        char* strPtrn = (char*)patternCpy.getUnsecureString();

        for(auto it = pwds.begin(); it != pwds.end(); it++)
        {
            SecureString description = (*it)->GetDescription();
            if(strcasestr((char*)description.getUnsecureString(), strPtrn) != NULL)
            {
                filtered.push_back((*it));
            }
            description.UnsecuredStringFinished();
        }

        patternCpy.UnsecuredStringFinished();
    } else {
        filtered = PwdVector(pwds.begin(), pwds.end());
    }

    if(labels.size() > 0)
    {
        for(auto iLabel = labels.begin(); iLabel != labels.end(); iLabel++)
        {
            PwdVector passed;
            for(auto iPwd = filtered.begin(); iPwd != filtered.end(); iPwd++)
            {
                if((*iPwd)->HasLabel(*iLabel))
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
    return CreatePwd(desciption, SecureString(), password);
}

Pwd* PwdList::CreatePwd(const SecureString& desciption, const SecureString& username, const SecureString& password)
{
    //check if pwd is unique
    for(auto it = pwds.begin(); it != pwds.end(); it++)
    {
        if((*it)->GetDescription().equals(desciption))
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
	Pwd* pwd = CreatePwd(desciption, username, password);
	pwd->SetCTime(created);
	pwd->SetMTime(modified);
	return pwd;
}

void PwdList::DeletePwd(Pwd* pwd)
{
    auto labels = pwd->GetLabels();
    for(auto label = labels.begin(); label != labels.end(); label++)
    {
        RemovePwdFromLabel(pwd, *label);
    }
    pwds.remove(pwd);
    delete pwd;
}

PwdLabelVector PwdList::AllLabels()
{
    existingLabels.sort(myLabelcompare);
    return PwdLabelVector(existingLabels.begin(), existingLabels.end());
}
            
PwdLabelVector PwdList::FilterLabels(SecureString pattern)
{
    PwdLabelVector vector;
    const char* strPtrn = pattern.getUnsecureString();
    for(auto it = existingLabels.begin(); it != existingLabels.end(); it++)
    {
        if(strstr(strPtrn, (*it).getUnsecureString()) != NULL)
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
    return pwds.size();
}

int PwdList::CountPwds(const SecureString& label)
{
    int count = 0;
    for(auto it = pwds.begin(); it != pwds.end(); it++)
    {
        if((*it)->HasLabel(label))
            count++;
    }
    return count++;
}

            
bool PwdList::AddPwdToLabel(Pwd* pwd, SecureString label)
{
    if(std::find(existingLabels.begin(), existingLabels.end(), label) == existingLabels.end())
    {
        existingLabels.push_back(label);
    }
    pwd->AddLabel(label);
    return false;
}

bool PwdList::RemovePwdFromLabel(Pwd* pwd, SecureString label)
{
    pwd->RemoveLabel(label);
    if(CountPwds(label) == 0)
    {
        existingLabels.remove(label);
    }
    return false;
}

bool PwdList::ValidateDescription(Pwd* pwd, const SecureString& newDescription)
{
	//check if pwd is unique
	for (auto it = pwds.begin(); it != pwds.end(); it++)
	{
		if ((*it) != pwd && (*it)->GetDescription().equals(newDescription))
			return false;
	}
	return true;
}