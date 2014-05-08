#ifndef SERVER_H
#define SERVER_H

#include "SecureString/SecureString.h"
#include <string>

namespace Kryptan
{
    namespace Core
    {
        class Server
        {
        public:
            enum Status
            {
                WAITING_FOR_START,
                WAITING_FOR_CONNECTION,
                SENDING_CONTENT,
                WAITING_FOR_CONTENT,
                RECEIVING_CONTENT,
                FINISHED,
                ABORTING,
                ABORTED,
                SERVER_ERROR
            };

            static const char STOPSTRING;

            static Server* CreateServer(int port, std::string& serveContent);

            virtual Status GetStatus() = 0;

            virtual std::string GetErrorMessage() = 0;

            virtual void StartAsyncServe() = 0;

            virtual void AbortAsyncServe() = 0;

            virtual std::string getRecievedContent() = 0;

            virtual ~Server(){}
        };
    }
}

#endif