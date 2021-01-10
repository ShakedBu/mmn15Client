#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <boost/asio.hpp>
#include <fstream>
#include <filesystem>
#include <boost/filesystem.hpp>
#include <stdio.h>
#include <stdlib.h>
using namespace std;

using boost::asio::ip::tcp;

enum { max_length = 1024,
        mex_user_length = 16};
enum Action {
    Exit = 0,
    Register = 1,
    ClientList = 2,
    PublicKey = 3,
    WaitingMessages = 4,
    SendTextMessage = 5,
    SendFile = 50,
    RequestKey = 51,
    SendKey = 52
};

int main(int argc, char* argv[])
{
    try
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
                cout << host << endl;

                if (serverfile.good())
                {
                    // Get port
                    getline(serverfile, port, ':');
                    cout << port << endl;
                }
            }

            serverfile.close();
        }


        boost::asio::io_context io_context;

        tcp::socket s(io_context);
        tcp::resolver resolver(io_context);
        boost::asio::connect(s, resolver.resolve(host.c_str(), port.c_str()));

        char* user = new char[mex_user_length];
        char* message = new char[max_length];
        char* uid = new char[16];
        string action;
        boost::filesystem::path userfile("me.info");
        ofstream myfile;

        while (true) {
            memset(user, 0, sizeof user);
            memset(message, 0, sizeof message);

            std::cout << "MessageU client at your service! " << std::endl <<
                "1) Register" << std::endl <<
                "2) Request for client list" << std::endl <<
                "3) Request for public key" << std::endl <<
                "4) Request for waiting messages" << std::endl <<
                "5) Send a text message" << std::endl <<
                "51) Send a request for symmetric key" << std::endl <<
                "52) Send your semmetric key" << std::endl <<
                "0) Exit client" << std::endl;

            action = "";
            std::getline(std::cin, action);

            switch (std::stoi(action))
            {
                case Exit:
                    return 0;
                    break;

                case Register:
                    // Check wether user is already registered
                    if (boost::filesystem::exists(userfile)){
                        std::cout << "You are already registered." << std::endl;
                        break;
                    }

                    // Get user name and register user
                    myfile.open("me.info");
                    std::cout << "Enter tour name: ";
                    std::cin.getline(user, mex_user_length);
                    // Send to server
                    myfile << user << std::endl;
                    //myfile << uid;
                    myfile.close();
                    break;

                case ClientList:
                    break;

                case PublicKey:
                    break;

                case WaitingMessages:
                    break;

                case SendTextMessage:
                    std::cout << "To whom would you like to send a message? ";
                    std::cin.getline(user, mex_user_length);
                    std::cout << "Enter the message to be sent: " << std::endl;
                    std::cin.getline(message, max_length);

                    break;

                case RequestKey:
                    std::cout << "From whom would you like to request a symmetric key? ";
                    std::cin.getline(user, mex_user_length);

                    break;

                case SendKey:
                    std::cout << "To whom would you like to send a symmetric key? ";
                    std::cin.getline(user, mex_user_length);

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
        std::cerr << "server responded with an error" << std::endl << e.what() << std::endl;
    }

    return 0;
}