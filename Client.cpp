#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <boost/asio.hpp>
#include <fstream>
#include <filesystem>
#include <boost/filesystem.hpp>
#include <boost/archive/text_iarchive.hpp>
#include <boost/archive/text_oarchive.hpp>
//#include <boost/archive/binary_oarchive.hpp>
#include <boost/uuid/uuid.hpp>

using namespace std;
using boost::asio::ip::tcp;

enum {
    max_length = 1024,
    max_user_length = 255,
};
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
struct Request {
    char clientId[16];
    uint8_t version_ = 1;
    uint8_t code;
    uint32_t size;
    std::string paylod;
};
struct Response {
    int8_t version;
    int16_t code;
    unsigned int size;
    boost::uuids::uuid uuid;
    //std::string payload;
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


        boost::asio::io_context io_context;

        // Connect to server
        tcp::socket s(io_context);
        tcp::resolver resolver(io_context);
        boost::asio::connect(s, resolver.resolve(host.c_str(), port.c_str()));

        char user[max_user_length];
        char message[max_length];
        boost::uuids::uuid uuid;
        string userName;
        string uuid_str;
        string action;
        boost::filesystem::path userfile("me.info");
        ofstream myfile;
        ifstream myfile_i;
        Request request;
        size_t request_length;
        Response response;
        std::vector<boost::asio::const_buffer> buffers;

        // Get instructions from user
        while (true) {
            memset(user, 0, sizeof user);
            memset(message, 0, sizeof message);
            memset(&request, 0, sizeof request);
            memset(&response, 0, sizeof response);
            buffers.clear();
            action.clear();
            request.version_ = 1;

            //if (strlen(uid) != 0)
               //strcpy_s(request.clientId, uid);

            try
            {
                std::cout << "MessageU client at your service! " << std::endl <<
                    "1) Register" << std::endl <<
                    "2) Request for client list" << std::endl <<
                    "3) Request for public key" << std::endl <<
                    "4) Request for waiting messages" << std::endl <<
                    "5) Send a text message" << std::endl <<
                    "51) Send a request for symmetric key" << std::endl <<
                    "52) Send your semmetric key" << std::endl <<
                    "0) Exit client" << std::endl;

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
                            // If not the same run that registered - get uuid from file
                            if (uuid.is_nil()) {
                                myfile_i.open("me.info");
                                std::getline(myfile_i, userName);
                                std::getline(myfile_i, uuid_str);
                                myfile_i.close();
                                memcpy_s(&uuid, 16, uuid_str.c_str(), 16);
                            }
                            break;
                        }

                        // Get user name and register user
                        std::cout << "Enter tour name: ";
                        std::cin.getline(user, max_user_length);
                    
                        // Send to server
                        request.paylod = user;
                        request.code = 100;
                        request.size = strlen(user);

                        buffers.push_back(boost::asio::buffer(&request.clientId, 16));
                        buffers.push_back(boost::asio::buffer(&request.version_, 1));
                        buffers.push_back(boost::asio::buffer(&request.code, 1));
                        buffers.push_back(boost::asio::buffer(&request.size, 4));
                        buffers.push_back(boost::asio::buffer(user, strlen(user)));
                        boost::asio::write(s, buffers);
                        
                        boost::asio::read(s, boost::asio::buffer(&response, 24));

                        if (response.code == 1000) {
                            
                            uuid = response.uuid;
                            myfile.open("me.info");
                            myfile << user << std::endl << response.uuid.data;
                            myfile.close();
                        }
                        break;

                    case ClientList:
                        if (!boost::filesystem::exists(userfile)) {
                            std::cout << "You need to register first." << std::endl;
                            break;
                        }

                        std::copy(uuid.begin(), uuid.end(), request.clientId);
                        request.code = 101;
                        request.size = 0;

                        buffers.push_back(boost::asio::buffer(&request.clientId, 16));
                        buffers.push_back(boost::asio::buffer(&request.version_, 1));
                        buffers.push_back(boost::asio::buffer(&request.code, 1));
                        buffers.push_back(boost::asio::buffer(&request.size, 4));
                        boost::asio::write(s, buffers);
                        boost::asio::read(s, boost::asio::buffer(&response, max_length));

                        break;

                    case PublicKey:
                        if (!boost::filesystem::exists(userfile)) {
                            std::cout << "You need to register first." << std::endl;
                            break;
                        }
                        request.code = 102;

                        break;

                    case WaitingMessages:
                        if (!boost::filesystem::exists(userfile)) {
                            std::cout << "You need to register first." << std::endl;
                            break;
                        }
                        request.code = 104;
                        request.size = 0;

                        break;

                    case SendTextMessage:
                        if (!boost::filesystem::exists(userfile)) {
                            std::cout << "You need to register first." << std::endl;
                            break;
                        }
                        std::cout << "To whom would you like to send a message? ";
                        std::cin.getline(user, max_user_length);
                        std::cout << "Enter the message to be sent: " << std::endl;
                        std::cin.getline(message, max_length);

                        request.code = 104;

                        break;

                    case RequestKey:
                        if (!boost::filesystem::exists(userfile)) {
                            std::cout << "You need to register first." << std::endl;
                            break;
                        }
                        std::cout << "From whom would you like to request a symmetric key? ";
                        std::cin.getline(user, max_user_length);

                        request.code = 104;
                        request.size = 0;

                        break;

                    case SendKey:
                        if (!boost::filesystem::exists(userfile)) {
                            std::cout << "You need to register first." << std::endl;
                            break;
                        }
                        std::cout << "To whom would you like to send a symmetric key? ";
                        std::cin.getline(user, max_user_length);

                        request.code = 104;

                        break;

                    default:
                        std::cout << "Please enter a valid number." << std::endl;
                        break;
                }
            }
            catch (std::exception& e)
            {
                std::cerr << "server responded with an error" << std::endl << e.what() << std::endl;
            }
        }

        std::cout << "Enter message: ";
        char req[max_length];
        std::cin.getline(req, max_length);
        request_length = std::strlen(req);
        boost::asio::write(s, boost::asio::buffer(req, request_length));

        char reply[max_length];
        size_t reply_length = boost::asio::read(s,
            boost::asio::buffer(reply, request_length));
        std::cout << "Reply is: ";
        std::cout.write(reply, reply_length);
    }
    catch (std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}