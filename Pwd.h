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
#include "SecureString.h"

namespace Kryptan {
    namespace Core {

        typedef std::vector<SecureString> PwdLabelVector;

        class Pwd {
            //this class can only be instantiated by the PwdList class
            friend class PwdList;
        public:

            SecureString GetDescription() const;
            SecureString GetUsername() const;
            SecureString GetPassword() const;

            void SetDescription(const SecureString& desc);
            void SetUsername(const SecureString& usrname);
            void SetPassword(const SecureString& passwd);

            bool HasLabel(const SecureString& label){return std::find(mLabels.begin(), mLabels.end(), label) != mLabels.end();}
            PwdLabelVector GetLabels() { return PwdLabelVector(mLabels.begin(), mLabels.end()); }

        private:
            Pwd();
            Pwd(const Pwd& orig);
            virtual ~Pwd();

            void AddLabel(const SecureString& label){if(!HasLabel(label)) mLabels.push_back(label);}
            void RemoveLabel(const SecureString& label){mLabels.remove(label);}

            SecureString mDescription;
            SecureString mUsername;
            SecureString mPassword;

            std::list<SecureString> mLabels;
        };
    }
}

#endif	/* PWD_H */
