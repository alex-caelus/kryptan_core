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
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
	this->mValidator = validator;
	mTimeCreated = time(0);
	updateMTime();
}

Pwd::Pwd(const Pwd& orig) {
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
	mTimeCreated = orig.mTimeCreated;
	mTimeLastModified = orig.mTimeLastModified;
	mDescription.assign(orig.mDescription);
	mUsername.assign(orig.mUsername);
	mPassword.assign(orig.mPassword);
	mValidator = orig.mValidator;
}

Pwd::~Pwd() {
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
}

SecureString Pwd::GetDescription() const
{
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
	return mDescription;
}

SecureString Pwd::GetUsername() const
{
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
	return mUsername;
}

SecureString Pwd::GetPassword() const
{
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
	return mPassword;
}

time_t Pwd::GetTimeLastModified() const
{
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
	return mTimeLastModified;
}

std::string Pwd::GetTimeLastModifiedString() const
{
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
	return TimeToString(mTimeLastModified);
}

time_t Pwd::GetTimeCreated() const
{
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
	return mTimeCreated;
}

std::string Pwd::GetTimeCreatedString() const
{
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
	return TimeToString(mTimeCreated);
}


void Pwd::SetDescriptionNoMTime(const SecureString& desc)
{
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
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
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
	mUsername.assign(usrname);
}

void Pwd::SetPasswordNoMTime(const SecureString& passwd)
{
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
	mPassword.assign(passwd);
}

void Pwd::SetDescription(const SecureString& desc)
{
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
	SetDescriptionNoMTime(desc);
	updateMTime();
}

void Pwd::SetUsername(const SecureString& usrname)
{
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
	SetUsernameNoMTime(usrname);
	updateMTime();
}

void Pwd::SetPassword(const SecureString& passwd)
{
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
	SetPasswordNoMTime(passwd);
	updateMTime();
}

void Pwd::updateMTime()
{
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
	mTimeLastModified = time(0);
}

void Pwd::SetMTime(time_t t)
{
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
	mTimeLastModified = t;
}

void Pwd::SetCTime(time_t t)
{
	std::lock_guard<std::recursive_mutex> lock(mutex_lock);
	mTimeCreated = t;
}
