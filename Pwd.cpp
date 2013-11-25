/* 
 * File:   Pwd.cpp
 * Author: alexander
 * 
 * Created on July 17, 2013, 5:48 PM
 */

#include "Pwd.h"

using namespace Kryptan::Core;

Pwd::Pwd() {
}

Pwd::Pwd(const Pwd& orig) {
	mDescription.assign(orig.mDescription);
	mUsername.assign(orig.mUsername);
	mPassword.assign(orig.mPassword);
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


void Pwd::SetDescription(const SecureString& desc)
{
	mDescription.assign(desc);
}

void Pwd::SetUsername(const SecureString& usrname)
{
	mUsername.assign(usrname);
}

void Pwd::SetPassword(const SecureString& passwd)
{
	mPassword.assign(passwd);
}
