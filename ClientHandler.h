#pragma once
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <boost/asio.hpp>
#include <fstream>
#include <filesystem>
#include <boost/filesystem.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>

#include "structs.h"

using namespace std;
using boost::asio::ip::tcp;

class ClientHandler
{
public:
	tcp::socket _socket;
	boost::uuids::uuid uuid;

	ClientHandler(boost::asio::io_context& io_context);

	bool registerClient();
	void getClientList();
};

