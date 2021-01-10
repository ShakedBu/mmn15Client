#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <boost/asio.hpp>
#include <fstream>

using namespace std;
using boost::asio::ip::tcp;

enum { max_length = 1024 };
enum Action {
    Exit = 0,
    Register = 1,
    ClientList = 2,
    PublicKey = 3,
    WaitingMessages = 4,
    SendTextMessage = 5,
    RequestKey = 51,
    SendKey = 52
};

int main(int argc, char* argv[])
{
    try
    {
        // Default host and port values
        const char* host = "localhost";
        const char* port = "1234";

        // Get server's host and port from ths file
        string serverInfo;
        ifstream myfile("server.info");
        if (myfile.is_open())
        {
            if (myfile.good())
            {
                // Get host
                getline(myfile, serverInfo, ':');
                host = serverInfo.c_str();
                cout << serverInfo << endl;

                if (myfile.good())
                {
                    // Get port
                    getline(myfile, serverInfo, ':');
                    port = serverInfo.c_str();
                    cout << serverInfo << endl;
                }
            }

            myfile.close();
        }


        boost::asio::io_context io_context;

        tcp::socket s(io_context);
        tcp::resolver resolver(io_context);
        boost::asio::connect(s, resolver.resolve(host, port));

        while (true) {
            std::cout << "MessageU client at your service! " << std::endl <<
                "1) Register" << std::endl <<
                "2) Request for client list" << std::endl <<
                "3) Request for public key" << std::endl <<
                "4) Request for waiting messages" << std::endl <<
                "5) Send a text message" << std::endl <<
                "51) Send a request for symmetric key" << std::endl <<
                "52) Send your semmetric key" << std::endl <<
                "0) Exit client" << std::endl;

            int action;
            std::cin >> action;

            switch (action)
            {
                case Exit:
                    return 0;
                    break;
                case Register:
                    break;
                case ClientList:
                    break;
                case PublicKey:
                    break;
                case WaitingMessages:
                    break;
                case SendTextMessage:
                    break;
                case RequestKey:
                    break;
                case SendKey:
                    break;
                default:
                    std::cout << "Please enter a valid number." << std::endl;
                    break;
            }
        }

        std::cout << "Enter message: ";
        char request[max_length];
        std::cin.getline(request, max_length);
        size_t request_length = std::strlen(request);
        boost::asio::write(s, boost::asio::buffer(request, request_length));

        char reply[max_length];
        size_t reply_length = boost::asio::read(s,
            boost::asio::buffer(reply, request_length));
        std::cout << "Reply is: ";
        std::cout.write(reply, reply_length);
        std::cout << "\n";
    }
    catch (std::exception& e)
    {
        std::cerr << "server responded with an error" << std::endl;
    }

    return 0;
}