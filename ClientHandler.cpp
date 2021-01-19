#include "ClientHandler.h"

ClientHandler::ClientHandler(boost::asio::io_context& io_context) : _socket(io_context)
{
	// Default host and port values
	// Get server's host and port from ths file
	string host = "localhost";
	string port = "1234";
	ifstream serverfile("server.info");
	if (serverfile.is_open())
	{
		if (serverfile.good())
		{
			// Get host
			getline(serverfile, host, ':');
			cout << host << ":";

			if (serverfile.good())
			{
				// Get port
				getline(serverfile, port, ':');
				cout << port << endl;
			}
		}

		serverfile.close();
	}

	// Connect to server
	tcp::resolver resolver(io_context);
	boost::asio::connect(_socket, resolver.resolve(host.c_str(), port.c_str()));
}

bool ClientHandler::registerClient()
{
	return false;
}

void ClientHandler::getClientList()
{
}
