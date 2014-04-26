/* 
 * File:   Pwd.cpp
 * Author: alexander
 * 
 * Created on July 17, 2013, 5:48 PM
 */

#include "Pwd.h"
#include <ctime>

using namespace Kryptan::Core;

std::string TimeToString(const time_t t)
{
	struct tm  tstruct;
	char       buf[80];
#ifdef _WIN32
	localtime_s(&tstruct, &t);
#else
	tstruct = *localtime(&t);
#endif
	// Visit http://en.cppreference.com/w/cpp/chrono/c/strftime
	// for more information about date/time format
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tstruct);

	return std::string(buf);
}

Pwd::Pwd(Internal::PwdDescriptionValidator* validator) {
	this->mValidator = validator;
	mTimeCreated = time(0);
	updateMTime();
}

Pwd::Pwd(const Pwd& orig) {
	mTimeCreated = orig.mTimeCreated;
	mTimeLastModified = orig.mTimeLastModified;
	mDescription.assign(orig.mDescription);
	mUsername.assign(orig.mUsername);
	mPassword.assign(orig.mPassword);
	mValidator = orig.mValidator;
}

Pwd::~Pwd() {
}

SecureString Pwd::GetDescription() const
{
	return mDescription;
}

SecureString Pwd::GetUsername() const
{
	return mUsername;
}

SecureString Pwd::GetPassword() const
{
	return mPassword;
}

time_t Pwd::GetTimeLastModified() const
{
	return mTimeLastModified;
}

std::string Pwd::GetTimeLastModifiedString() const
{
	return TimeToString(mTimeLastModified);
}

time_t Pwd::GetTimeCreated() const
{
	return mTimeCreated;
}

std::string Pwd::GetTimeCreatedString() const
{
	return TimeToString(mTimeCreated);
}


void Pwd::SetDescriptionNoMTime(const SecureString& desc)
{
	if (mValidator->ValidateDescription(this, desc))
	{
		mDescription.assign(desc);
	}
	else
	{
		throw KryptanDuplicatePwdException("A password with that description already exists!");
	}
}

void Pwd::SetUsernameNoMTime(const SecureString& usrname)
{
	mUsername.assign(usrname);
}

void Pwd::SetPasswordNoMTime(const SecureString& passwd)
{
	mPassword.assign(passwd);
}

void Pwd::SetDescription(const SecureString& desc)
{
	SetDescriptionNoMTime(desc);
	updateMTime();
}

void Pwd::SetUsername(const SecureString& usrname)
{
	SetUsernameNoMTime(usrname);
	updateMTime();
}

void Pwd::SetPassword(const SecureString& passwd)
{
	SetPasswordNoMTime(passwd);
	updateMTime();
}

void Pwd::updateMTime()
{
	mTimeLastModified = time(0);
}

void Pwd::SetMTime(time_t t)
{
	mTimeLastModified = t;
}

void Pwd::SetCTime(time_t t)
{
	mTimeCreated = t;
}
