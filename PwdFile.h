#ifndef PWDFILE_H
#define PWDFILE_H

#include <string>
#include "SecureString.h"
#include "PwdList.h"

namespace Kryptan {
    namespace Core {

        class PwdFile {
        public:
            PwdFile(std::string filename);
            ~PwdFile(void);

            void CreateNew();
            void OpenAndParse(SecureString masterkey, bool useOldFormat = false);
            void Save(SecureString masterkey);
            std::string SaveToString(SecureString masterkey, int mashIterations = 0);
            SecureString GetCurrentContent();
            void ReplaceContent(SecureString masterkey, std::string content);

            PwdList* GetPasswordList();
            std::string GetFilename();

            bool IsOpen();
            bool Exists();

        private:
            PwdFile(const PwdFile& obj);

            std::string filename;
            PwdList* list;

            bool isOpen;

            //only allow one thread to access this object at a time
            std::recursive_mutex mutex_lock;
        };

    }
}

#endif