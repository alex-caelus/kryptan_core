#ifndef PWDLIST_H
#define PWDLIST_H

#include <string>
#include <list>
#include <mutex>
#include "Pwd.h"
#include "SecureString.h"

namespace Kryptan {
    namespace Core {

        class PwdList : Internal::PwdDescriptionValidator{
            //this clas can only be created by PwdFile
            friend class PwdFileWorker;
        public:

            typedef std::vector<Pwd*> PwdVector;

            PwdVector All();
            PwdVector Filter(const SecureString& pattern);
            PwdVector Filter(const PwdLabelVector& labels);
            PwdVector Filter(const SecureString& pattern, const PwdLabelVector& labels);

            Pwd* CreatePwd(const SecureString& desciption, const SecureString& password);
            Pwd* CreatePwd(const SecureString& desciption, const SecureString& username, const SecureString& password);
            void DeletePwd(Pwd* pwd);
            
            PwdLabelVector AllLabels();
            PwdLabelVector FilterLabels(SecureString pattern);
            int CountPwds();
            int CountPwds(const SecureString& label);
            
            bool AddPwdToLabel(Pwd* pwd, SecureString label);
            bool RemovePwdFromLabel(Pwd* pwd, SecureString label);

			bool ValidateDescription(Pwd* pwd, const SecureString& newDescription) override;

			void ImportPwd(Pwd* pwd);

        private:
            PwdList(void);
            virtual ~PwdList(void);
            PwdList(const PwdList& obj);

			//only accessible to PwdFileWorker
			Pwd* CreatePwd(const SecureString& desciption, const SecureString& username, const SecureString& password, time_t created, time_t modified);
			//only accessible to PwdFileWorker
			bool AddPwdToLabelNoMTime(Pwd* pwd, SecureString label);

            std::list<Pwd*> pwds;
            std::list<SecureString> existingLabels;

			//only allow one thread to access this object at a time
			std::recursive_mutex mutex_lock;

        };
    }
}

#endif
