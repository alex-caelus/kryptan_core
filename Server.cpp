#ifndef KRYPTAN_CORE_DO_NOT_USE_SERVER
#include "Server.h"
#include <algorithm>
#include <cstdio>
#include <boost/asio.hpp>
#include <boost/thread.hpp>

using namespace Kryptan::Core;
using boost::asio::io_service;
using boost::asio::ip::tcp;

const char Server::STOPSTRING = '#';

/////////////SERVER IMPLEMENTATION////////////////

class ServerTask
{
public:
	ServerTask(int port, std::string& serveContent, io_service* io_ser)
		: currentState(Server::WAITING_FOR_START),
		io_ser(io_ser),
		acceptor(*io_ser, tcp::endpoint(tcp::v4(), port)),
		socket(*io_ser),
		servableContent(serveContent)
	{
	}

	// make object callable
	// this is the starting point of the thread
	void operator()()
	{
		//put a job in the io_service to accept ONE incomming connection
		acceptor.async_accept(socket, boost::bind(&ServerTask::HandleAccept, this, boost::asio::placeholders::error));

		//current status
		currentState = Server::WAITING_FOR_CONNECTION;

		//start listening to requests, this blocks until
		io_ser->run();

		if (currentState != Server::FINISHED && currentState != Server::SERVER_ERROR && currentState != Server::ABORTING)
		{
			currentState = Server::SERVER_ERROR;
			if (errorMessage.empty())
				errorMessage = "IO_SERVICE: No more jobs to do!";
		}
	} 

	//Step 1: an incomming connection has been accepted
	//So let's send the client some data
	void HandleAccept(const boost::system::error_code& ec)
	{
		if (ec)
		{
			errorMessage = ec.message();
			currentState = Server::SERVER_ERROR;
			io_ser->stop();
			return;
		}

		//current status
		currentState = Server::SENDING_CONTENT;

		boost::asio::async_write(socket, boost::asio::buffer(servableContent), boost::bind(&ServerTask::HandleContentWrite, this, boost::asio::placeholders::error));
	}

	//Step 2: The content has been sent to the client
	//so let's wait for a response
	void HandleContentWrite(const boost::system::error_code& ec)
	{
		if (ec)
		{
			errorMessage = ec.message();
			currentState = Server::SERVER_ERROR;
			io_ser->stop();
			return;
		}

		//current status
		currentState = Server::WAITING_FOR_CONTENT;
		addReadUntilStopCharacterToService();
	}

	void addReadUntilStopCharacterToService()
	{
		boost::asio::async_read_until(socket, inBuf, Server::STOPSTRING, boost::bind(&ServerTask::HandleContentRecieved, this, boost::asio::placeholders::error));
	}

	//Step 3: Content has been recieved form the client
	//lets continue to recive until we encounter a null character
	//that indicates a end of the string
	void HandleContentRecieved(const boost::system::error_code& ec)
	{
		if (ec)
		{
			errorMessage = ec.message();
			currentState = Server::SERVER_ERROR;
			io_ser->stop();
		}
		else
		{
			//final content recieved
			std::istream is(&inBuf);
			std::getline(is, recievedContent, Server::STOPSTRING); //changed delimiter to Server::STOPSTRING
			currentState = Server::FINISHED;
		}
	}

	void Reset()
	{
		currentState = Server::WAITING_FOR_START;
		errorMessage = "";
		recievedContent = "";
	}

	std::string getRecievedContent()
	{
		return recievedContent;
	}

	Server::Status getCurrentStatus()
	{
		return currentState;
	}

	std::string getErrorMessage()
	{
		return errorMessage;
	}

	~ServerTask()
	{
	}

private:
	typedef boost::shared_ptr<boost::asio::streambuf >streambuf_ptr;
	boost::asio::streambuf inBuf;

	std::string errorMessage;
	io_service* io_ser;
	tcp::acceptor acceptor;
	tcp::socket socket;
	Server::Status currentState;
	std::string servableContent;
	std::string recievedContent;
};

class ServerImpl : public Server
{
public:
	ServerImpl::ServerImpl(int port, std::string& serveContent)
		: io_ser(new io_service()), task(port, serveContent, io_ser),
		thread(NULL)
	{
	}

	Server::Status GetStatus() override
	{
		return task.getCurrentStatus();
	}

	std::string GetErrorMessage() override
	{
		return task.getErrorMessage();
	}

	void StartAsyncServe() override
	{
		if (thread)
			AbortAsyncServe();
		task.Reset();
		thread = new boost::thread(boost::ref(task));
	}


	void AbortAsyncServe() override
	{
		io_ser->stop();
		thread->interrupt();
		thread->join();
		delete thread;
		thread = NULL;
	}

	std::string getRecievedContent() override
	{
		return task.getRecievedContent();
	}

	~ServerImpl()
	{
		AbortAsyncServe();
		//delete io_ser; //no need
	}

private:
	io_service* io_ser;
	boost::thread* thread;
	ServerTask task;
};

Server* Server::CreateServer(int port, std::string& serveContent)
{
	return new ServerImpl(port, serveContent);
}

#endif
