/* 
 * File:   Pwd.h
 * Author: alexander
 *
 * Created on July 17, 2013, 5:48 PM
 */

#ifndef PWD_H
#define	PWD_H

#include <vector>
#include <algorithm>
#include <list>
#include <mutex>
#include "Exceptions.h"
#include "SecureString.h"

namespace Kryptan {
	namespace Core {

		//forward declaration
		class Pwd;

		namespace Internal{
			class PwdDescriptionValidator{
			public:
				virtual bool ValidateDescription(Pwd* pwd, const SecureString &newDescription) = 0;
			};
		}

        typedef std::vector<SecureString> PwdLabelVector;

        class Pwd {
            //this class can only be instantiated by the PwdList class
            friend class PwdList;
        public:

            SecureString GetDescription() const;
			SecureString GetUsername() const;
			SecureString GetPassword() const;

			time_t GetTimeLastModified() const;
			std::string GetTimeLastModifiedString() const;
			time_t GetTimeCreated() const;
			std::string GetTimeCreatedString() const;

            void SetDescription(const SecureString& desc);
            void SetUsername(const SecureString& usrname);
            void SetPassword(const SecureString& passwd);

			bool HasLabel(const SecureString& label){
				std::lock_guard<std::recursive_mutex> lock(mutex_lock); 
				return std::find(mLabels.begin(), mLabels.end(), label) != mLabels.end();
			}
			PwdLabelVector GetLabels() {
				std::lock_guard<std::recursive_mutex> lock(mutex_lock); 
				return PwdLabelVector(mLabels.begin(), mLabels.end());
			}

        private:
			Pwd(Internal::PwdDescriptionValidator* validator);
            Pwd(const Pwd& orig);
            virtual ~Pwd();

			void SetCTime(time_t);
			void SetMTime(time_t);
			void AddLabel(const SecureString& label){
				std::lock_guard<std::recursive_mutex> lock(mutex_lock); 
				if (!HasLabel(label)) mLabels.push_back(label);
			}
			void RemoveLabel(const SecureString& label){
				std::lock_guard<std::recursive_mutex> lock(mutex_lock); 
				mLabels.remove(label);
			}


			void SetDescriptionNoMTime(const SecureString& desc);
			void SetUsernameNoMTime(const SecureString& usrname);
			void SetPasswordNoMTime(const SecureString& passwd);

			void updateMTime();

            SecureString mDescription;
            SecureString mUsername;
            SecureString mPassword;

			time_t mTimeCreated;
			time_t mTimeLastModified;

            std::list<SecureString> mLabels;
			Internal::PwdDescriptionValidator* mValidator;

			//only allow one thread to access this object at a time
			mutable std::recursive_mutex mutex_lock;
		};
    }
}

#endif	/* PWD_H */

