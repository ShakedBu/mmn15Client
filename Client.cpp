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

        // Declare variables
        char user[max_user_length];
        char message[max_length];
        char uid_arr[32];
        boost::uuids::uuid uuid;
        boost::uuids::uuid other_uuid;
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

        RegisterResponse register_response;
        UsersResponse users_list;;
        int user_num;
        SentResponse sent_response;
        OutMessage out_message;
        InMessage in_message;

        // Get instructions from user
        while (true) {
            memset(user, 0, sizeof user);
            memset(message, 0, sizeof message);
            memset(&request, 0, sizeof request);
            memset(&response, 0, sizeof response);
            buffers.clear();
            action.clear();
            request.version_ = 1;

            if (!uuid.is_nil())
                std::copy(uuid.begin(), uuid.end(), request.clientId);

            try
            {
                std::cout << std::endl << "MessageU client at your service! " << std::endl <<
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
                        s.close();
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
                                uuid = boost::lexical_cast<boost::uuids::uuid>(uuid_str);
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

                        buffers.push_back(boost::asio::buffer(&request.clientId, user_id_length));
                        buffers.push_back(boost::asio::buffer(&request.version_, 1));
                        buffers.push_back(boost::asio::buffer(&request.code, 1));
                        buffers.push_back(boost::asio::buffer(&request.size, 4));
                        buffers.push_back(boost::asio::buffer(user, strlen(user)));
                        // TODO: add public key!
                        //buffers.push_back(boost::asio::buffer(public_key, 32));
                        boost::asio::write(s, buffers);
                        
                        boost::asio::read(s, boost::asio::buffer(&response, 24));
                        memcpy_s(&register_response, user_id_length, &response.payload, user_id_length);

                        if (response.code == 1000) {
                            
                            uuid = register_response.uuid;
                            uuid_str = boost::uuids::to_string(uuid);
                            myfile.open("me.info");
                            myfile << user << std::endl << uuid_str;
                            myfile.close();
                        }
                        break;

                    case ClientList:
                        if (!boost::filesystem::exists(userfile)) {
                            std::cout << "You need to register first." << std::endl;
                            break;
                        }

                        request.code = 101;
                        request.size = 0;

                        buffers.push_back(boost::asio::buffer(&request.clientId, user_id_length));
                        buffers.push_back(boost::asio::buffer(&request.version_, 1));
                        buffers.push_back(boost::asio::buffer(&request.code, 1));
                        buffers.push_back(boost::asio::buffer(&request.size, 4));
                        boost::asio::write(s, buffers);

                        boost::asio::read(s, boost::asio::buffer(&response, 7));

                        if (response.code == 1001 && response.size > 0) {
                            user_num = response.size / (16 + 255);
                             std::cout << "Cleints list:" << std::endl;

                            // Go over the clients and print them
                            for (size_t i = 0; i < user_num; i++)
                            {
                                boost::asio::read(s, boost::asio::buffer(&users_list, sizeof users_list));
                                uuid_str = boost::uuids::to_string(users_list.uuid);
                                std::cout << (i+1) << ". " << uuid_str.c_str() << " " << users_list.clientName << std::endl;
                            }
                        }

                        break;

                    case PublicKey:
                        if (!boost::filesystem::exists(userfile)) {
                            std::cout << "You need to register first." << std::endl;
                            break;
                        }

                        std::cout << "Whose public key would you like to request? (enter index)";
                        std::getline(std::cin, action);
                        user_num = std::stoi(action);
                        user_num -= 1;

                        if (user_num < 0 || user_num > sizeof(users_list)/sizeof(UsersResponse) ){
                            std::cout << "no such user!" << std::endl;
                        }


                        request.code = 102;
                        request.size = 0;

                        buffers.push_back(boost::asio::buffer(&request.clientId, user_id_length));
                        buffers.push_back(boost::asio::buffer(&request.version_, 1));
                        buffers.push_back(boost::asio::buffer(&request.code, 1));
                        buffers.push_back(boost::asio::buffer(&request.size, 4));
                        //buffers.push_back(boost::asio::buffer(&users_list[user_num], 16));
                        boost::asio::write(s, buffers);

                        s.read_some(boost::asio::buffer(&response, max_length));

                        break;

                    case WaitingMessages:
                        if (!boost::filesystem::exists(userfile)) {
                            std::cout << "You need to register first." << std::endl;
                            break;
                        }
                        request.code = 104;
                        request.size = 0;

                        buffers.push_back(boost::asio::buffer(&request.clientId, user_id_length));
                        buffers.push_back(boost::asio::buffer(&request.version_, 1));
                        buffers.push_back(boost::asio::buffer(&request.code, 1));
                        buffers.push_back(boost::asio::buffer(&request.size, 4));
                        boost::asio::write(s, buffers);

                        s.read_some(boost::asio::buffer(&response, max_length));

                        if (response.code == 1004 && response.size > 0) {

                            memcpy_s(&in_message, response.size, &response.payload, response.size);
                            // Go over messages.
                            
                        }
                        break;

                    case SendTextMessage:
                        if (!boost::filesystem::exists(userfile)) {
                            std::cout << "You need to register first." << std::endl;
                            break;
                        }
                        std::cout << "To whom would you like to send a message? (enter index)";
                        std::getline(std::cin, action);
                        user_num = std::stoi(action);
                        user_num -= 1;

                        if (user_num < 0 || user_num > sizeof(users_list) / sizeof(UsersResponse)) {
                            std::cout << "no such user!" << std::endl;
                            break;
                        }
                        std::cout << "Enter the message to be sent: " << std::endl;
                        std::cin.getline(message, max_length);

                        request.code = 104;
                        request.size = 0;
                        out_message.content = message;
                        out_message.size = sizeof(out_message.content);
                        out_message.type = 3;
                        //out_message.uuid_to = users_list[user_num].uuid;

                        buffers.push_back(boost::asio::buffer(&request.clientId, user_id_length));
                        buffers.push_back(boost::asio::buffer(&request.version_, 1));
                        buffers.push_back(boost::asio::buffer(&request.code, 1));
                        buffers.push_back(boost::asio::buffer(&request.size, 4));
                        buffers.push_back(boost::asio::buffer(&out_message.uuid_to, 16));
                        buffers.push_back(boost::asio::buffer(&out_message.type, 1));
                        buffers.push_back(boost::asio::buffer(&out_message.size, 4));
                        buffers.push_back(boost::asio::buffer(&out_message.content, out_message.size));
                        boost::asio::write(s, buffers);

                        s.read_some(boost::asio::buffer(&response, max_length));

                        break;

                    case RequestKey:
                        if (!boost::filesystem::exists(userfile)) {
                            std::cout << "You need to register first." << std::endl;
                            break;
                        }
                        std::cout << "From whom would you like to request a symmetric key? (enter index)";
                        std::getline(std::cin, action);
                        user_num = std::stoi(action);
                        user_num -= 1;

                        if (user_num < 0 || user_num > sizeof(users_list) / sizeof(UsersResponse)) {
                            std::cout << "no such user!" << std::endl;
                            break;
                        }

                        request.code = 102;
                        request.size = 0;
                        out_message.size = 0;
                        out_message.type = 1;
                        //out_message.uuid_to = users_list[user_num].uuid;

                        buffers.push_back(boost::asio::buffer(&request.clientId, user_id_length));
                        buffers.push_back(boost::asio::buffer(&request.version_, 1));
                        buffers.push_back(boost::asio::buffer(&request.code, 1));
                        buffers.push_back(boost::asio::buffer(&request.size, 4));
                        buffers.push_back(boost::asio::buffer(&out_message.uuid_to, 16));
                        buffers.push_back(boost::asio::buffer(&out_message.type, 1));
                        buffers.push_back(boost::asio::buffer(&out_message.size, 4));
                        boost::asio::write(s, buffers);

                        s.read_some(boost::asio::buffer(&response, max_length));

                        break;

                    case SendKey:
                        if (!boost::filesystem::exists(userfile)) {
                            std::cout << "You need to register first." << std::endl;
                            break;
                        }
                        std::cout << "To whom would you like to send a symmetric key? (enter index)";
                        std::getline(std::cin, action);
                        user_num = std::stoi(action);
                        user_num -= 1;

                        if (user_num < 0 || user_num > sizeof(users_list) / sizeof(UsersResponse)) {
                            std::cout << "no such user!" << std::endl;
                            break;
                        }

                        request.code = 102;
                        request.size = 0;
                        out_message.size = 128;
                        out_message.type = 2;
                        //out_message.uuid_to = users_list[user_num].uuid;
                        out_message.content = "";// TODO: sym key

                        buffers.push_back(boost::asio::buffer(&request.clientId, user_id_length));
                        buffers.push_back(boost::asio::buffer(&request.version_, 1));
                        buffers.push_back(boost::asio::buffer(&request.code, 1));
                        buffers.push_back(boost::asio::buffer(&request.size, 4));
                        buffers.push_back(boost::asio::buffer(&out_message.uuid_to, 16));
                        buffers.push_back(boost::asio::buffer(&out_message.type, 1));
                        buffers.push_back(boost::asio::buffer(&out_message.size, 4));
                        buffers.push_back(boost::asio::buffer(&out_message.content, out_message.size));
                        boost::asio::write(s, buffers);

                        s.read_some(boost::asio::buffer(&response, max_length));

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
    }
    catch (std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}

void handler(const boost::system::error_code& error, std::size_t bytes_transferred)
{
}
