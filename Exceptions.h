#ifndef EXCEPTIONS_H
#define EXCEPTIONS_H

#include <stdexcept>
#include <string>

namespace Kryptan
{
    namespace Core
    {
        class KryptanBaseException : public std::runtime_error
        {
        public:
            KryptanBaseException(const std::string& msg)
                : std::runtime_error(msg)
            {
            }
        };

        class KryptanFileNotReadableException : public KryptanBaseException
        {
        public:
            KryptanFileNotReadableException(const std::string& msg)
                : KryptanBaseException(msg)
            {
            }
        };

        class KryptanFileNotWritableException : public KryptanBaseException
        {
        public:
            KryptanFileNotWritableException(const std::string& msg)
                : KryptanBaseException(msg)
            {
            }
        };

        class KryptanFileContentException : public KryptanBaseException
        {
        public:
            KryptanFileContentException(const std::string& msg)
                : KryptanBaseException(msg)
            {
            }
        };

        class KryptanFileVersionException : public KryptanBaseException
        {
        public:
            KryptanFileVersionException(const std::string& msg)
                : KryptanBaseException(msg)
            {
            }
        };

        class KryptanDecryptException : public KryptanBaseException
        {
        public:
            KryptanDecryptException(const std::string& msg)
                : KryptanBaseException(msg)
            {
            }
        };

        class KryptanEncryptException : public KryptanBaseException
        {
        public:
            KryptanEncryptException(const std::string& msg)
                : KryptanBaseException(msg)
            {
            }
        };

        /*
         * Deprecated, use KryptanDecryptMacBadException instead.
         */
        class KryptanDecryptWrongKeyException : public KryptanDecryptException
        {
        public:
            KryptanDecryptWrongKeyException(const std::string& msg)
                : KryptanDecryptException(msg)
            {
            }
        };

        class KryptanDecryptMacBadException : public KryptanDecryptException
        {
        public:
            KryptanDecryptMacBadException(const std::string& msg)
                : KryptanDecryptException(msg)
            {
            }
        };

        class KryptanDuplicatePwdException : public KryptanBaseException
        {
        public:
            KryptanDuplicatePwdException(const std::string& msg)
                : KryptanBaseException(msg)
            {
            }
        };
    }
}

#endif