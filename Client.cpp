//#include "dll.h"
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <boost/filesystem.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <base64.h>
#include <rsa.h>

#include "cryptlib.h"
#include "osrng.h"
#include "SecBlock.h"
#include "structs.h"
#include "aes.h"
#include "modes.h"

using namespace std;
using namespace CryptoPP;
using boost::asio::ip::tcp;
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::AES;
using CryptoPP::CFB_Mode;

using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

char* generate_key(char* buff, size_t size)
{
    for (size_t i = 0; i < size; i += 4)
        _rdrand32_step(reinterpret_cast<unsigned int*>(&buff[i]));
    return buff;
}

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
                // get host
                getline(serverfile, host, ':');
                cout << host << ":";

                if (serverfile.good())
                {
                    // get port
                    getline(serverfile, port, ':');
                    cout << port << endl;
                }
            }
            serverfile.close();
        }
        
        // Connect to server
        boost::asio::io_context io_context;
        tcp::socket s(io_context);
        tcp::resolver resolver(io_context);
        boost::asio::connect(s, resolver.resolve(host.c_str(), port.c_str()));

        // Not changing between loops
        boost::uuids::uuid uuid;
        std::vector<User> users;

        // Files
        boost::filesystem::path userfile("me.info");
        ofstream myfile;
        ifstream myfile_i;

        // General
        std::vector<boost::asio::const_buffer> buffers;
        Request request;
        string action;
        ResponseHeader response_header;
        char message[max_length];
        int user_num;

        // Registration
        char user[max_user_length];
        string userName;
        string uuid_str;
        RegisterResponse register_response;

        // Clients list
        UsersResponse users_list;

        // Message sending
        SentResponse sent_response;
        OutMessage out_message;

        // Waiting messages
        InMessageHeader in_message;
        char* message_content;

        PublicKeyResponse public_key;
        SymmKeyResponse symm_key;

        // Keys

        // Create RSA Keys
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::InvertibleRSAFunction privateKey;
        privateKey.Initialize(rng, 1024);
        RSA::PublicKey publicKey(privateKey);

        static const size_t KEYSIZE = 160;
        CryptoPP::byte buf[KEYSIZE];
        CryptoPP::ArraySink as(buf, KEYSIZE);
        publicKey.Save(as);

        // RSA Decryptor
        CryptoPP::RSAES_OAEP_SHA_Decryptor symm_d(privateKey);

        // AES
        CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
        memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);

        // Get instructions from user
        while (true) {
            memset(user, 0, sizeof user);
            memset(message, 0, sizeof message);
            memset(&request, 0, sizeof request);
            memset(&response_header, 0, sizeof response_header);
            memset(&users_list, 0, sizeof users_list);
            buffers.clear();
            action.clear();
            request.version_ = 1;

            if (!uuid.is_nil())
                std::copy(uuid.begin(), uuid.end(), request.clientId);

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

            try
            {
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
                        std::cout << "Enter your name: ";
                        std::cin.getline(user, max_user_length);
                    
                        // Send to server
                        request.paylod = user;
                        request.code = 100;
                        request.size = strlen(user) + 160;

                        buffers.push_back(boost::asio::buffer(&request.clientId, user_id_length));
                        buffers.push_back(boost::asio::buffer(&request.version_, 1));
                        buffers.push_back(boost::asio::buffer(&request.code, 1));
                        buffers.push_back(boost::asio::buffer(&request.size, 4));
                        buffers.push_back(boost::asio::buffer(user, strlen(user)));
                        buffers.push_back(boost::asio::buffer(&buf, 160));
                        boost::asio::write(s, buffers);       
                        boost::asio::read(s, boost::asio::buffer(&response_header, sizeof response_header));
                        
                        if (response_header.code == 1000) {
                            boost::asio::read(s, boost::asio::buffer(&register_response, sizeof register_response));
                            uuid = register_response.uuid;
                            uuid_str = boost::uuids::to_string(uuid);
                            myfile.open("me.info");
                            myfile << user << std::endl << uuid_str;
                            myfile.close();
                        }
                        else {
                            std::cout << "Error registering" << std::endl;
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
                        boost::asio::read(s, boost::asio::buffer(&response_header, sizeof response_header));

                        if (response_header.code == 1001 && response_header.size > 0) {
                            user_num = response_header.size / (16 + 255);
                            std::cout << "Clients list:" << std::endl;
                            users.clear();

                            // Go over the clients and print them
                            for (size_t i = 0; i < user_num; i++)
                            {
                                boost::asio::read(s, boost::asio::buffer(&users_list, sizeof users_list));

                                User new_user;
                                new_user.uuid = users_list.uuid;
                                new_user.clientName = users_list.clientName;
                                users.push_back(new_user);

                                uuid_str = boost::uuids::to_string(new_user.uuid);
                                std::cout << (i+1) << ". " << uuid_str.c_str() << " " << new_user.clientName << std::endl;
                            }
                        }

                        break;

                    case GetPublicKey:
                        if (!boost::filesystem::exists(userfile)) {
                            std::cout << "You need to register first." << std::endl;
                            break;
                        }

                        std::cout << "Whose public key would you like to request? (enter index)";
                        std::getline(std::cin, action);
                        user_num = std::stoi(action);
                        user_num -= 1;

                        if (user_num < 0 || user_num > users.size()){
                            std::cout << "no such user!" << std::endl;
                        }

                        request.code = 102;
                        request.size = 0;

                        buffers.push_back(boost::asio::buffer(&request.clientId, user_id_length));
                        buffers.push_back(boost::asio::buffer(&request.version_, 1));
                        buffers.push_back(boost::asio::buffer(&request.code, 1));
                        buffers.push_back(boost::asio::buffer(&request.size, 4));
                        buffers.push_back(boost::asio::buffer(&users[user_num].uuid, 16));
                        boost::asio::write(s, buffers);
                        boost::asio::read(s, boost::asio::buffer(&response_header, sizeof response_header));

                        if (response_header.code == 1002 && response_header.size > 0) {
                            boost::asio::read(s, boost::asio::buffer(&public_key, response_header.size));

                            CryptoPP::ArraySource as2(public_key.publicKey, KEYSIZE, true);

                            // Saves user's public key
                            for (size_t i = 0; i < users.size(); i++)
                            {
                                if (users[i].uuid == public_key.uuid) {
                                    users[i].publicKey.Load(as2);
                                    users[i].hasPublic = true;
                                }
                            }
                        }

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
                        boost::asio::read(s, boost::asio::buffer(&response_header, sizeof response_header));

                        if (response_header.code == 1004 && response_header.size > 0) {
                            int left = response_header.size;

                            std::cout << "Waiting messages: " << std::endl;

                            while (left > 0) {
                                // Go over messages.
                                boost::asio::read(s, boost::asio::buffer(&in_message, sizeof in_message));

                                User fromUser;
                                for (size_t i = 0; i < users.size(); i++)
                                {
                                    if (users[i].uuid == in_message.uuid_from) {
                                        fromUser = users[i];
                                        break;
                                    }
                                }

                                if (in_message.size > 0) {
                                    boost::asio::read(s, boost::asio::buffer(&message, in_message.size));
                                }

                                switch (in_message.type) {
                                case 1:
                                    std::cout << "From: " << fromUser.clientName << std::endl <<
                                        "Request for symmetric key" << std::endl;
                                    break;
                                case 2:
                                    if (strlen(message) > 0 && fromUser.hasPublic) {
                                        // Get other user's symmetric key
                                        std::string decrypted;
                                        CryptoPP::StringSource ss(message, true, new CryptoPP::PK_DecryptorFilter(rng, symm_d, new CryptoPP::ArraySink(fromUser.symKey, 16)));
                                        fromUser.hasSymm = true;
                                    }

                                    std::cout << "From: " << fromUser.clientName << std::endl <<
                                        "symmetric key received" << std::endl;
                                    break;
                                case 3:
                                    std::string decryptedtext;
                                    if (strlen(message) > 0 && fromUser.hasSymm) {
                                        CryptoPP::AES::Decryption aesDecryption(fromUser.symKey, CryptoPP::AES::DEFAULT_KEYLENGTH);
                                        CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

                                        CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
                                        stfDecryptor.Put(reinterpret_cast<const unsigned char*>(message), strlen(message));
                                        stfDecryptor.MessageEnd();
                                    }

                                    std::cout << "From: " <<  fromUser.clientName << std::endl <<
                                        "Content:" << std::endl << decryptedtext << std::endl;
                                    break;
                                }

                                left = left - sizeof in_message - in_message.size;
                            }

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

                        if (user_num < 0 || user_num > users.size()) {
                            std::cout << "no such user!" << std::endl;
                            break;
                        }

                        if (!users[user_num].hasSymm) {
                            std::cout << "no symmetric key for that user!" << std::endl;
                            break;
                        }
                        else {
                            std::cout << "Enter the message to be sent: " << std::endl;
                            std::cin.getline(message, max_length);

                            // Encrypt
                            std::string ciphertext;
                            
                            CryptoPP::AES::Encryption aesEncryption(users[user_num].symKey, CryptoPP::AES::DEFAULT_KEYLENGTH);
                            CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
                            CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(ciphertext));
                            stfEncryptor.Put(reinterpret_cast<const unsigned char*>(message), strlen(message));
                            stfEncryptor.MessageEnd();

                            request.code = 103;
                            request.size = sizeof out_message + strlen(message);
                            out_message.size = ciphertext.length();
                            out_message.type = 3;
                            out_message.uuid_to = users[user_num].uuid;

                            buffers.push_back(boost::asio::buffer(&request.clientId, user_id_length));
                            buffers.push_back(boost::asio::buffer(&request.version_, 1));
                            buffers.push_back(boost::asio::buffer(&request.code, 1));
                            buffers.push_back(boost::asio::buffer(&request.size, 4));
                            buffers.push_back(boost::asio::buffer(&out_message.uuid_to, 16));
                            buffers.push_back(boost::asio::buffer(&out_message.type, 1));
                            buffers.push_back(boost::asio::buffer(&out_message.size, 4));
                            buffers.push_back(boost::asio::buffer(&ciphertext, ciphertext.length()));
                            boost::asio::write(s, buffers);
                            boost::asio::read(s, boost::asio::buffer(&response_header, sizeof response_header));

                            if (response_header.code == 1003 && response_header.size > 0) {
                                // Read message id
                                boost::asio::read(s, boost::asio::buffer(&sent_response, sizeof sent_response));
                                std::cout << "Message sent - " << sent_response.id << std::endl;
                            }
                        }

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

                        if (user_num < 0 || user_num > users.size()) {
                            std::cout << "no such user!" << std::endl;
                            break;
                        }

                        request.code = 103;
                        request.size = 0;
                        out_message.size = 0;
                        out_message.type = 1;
                        out_message.uuid_to = users[user_num].uuid;

                        buffers.push_back(boost::asio::buffer(&request.clientId, user_id_length));
                        buffers.push_back(boost::asio::buffer(&request.version_, 1));
                        buffers.push_back(boost::asio::buffer(&request.code, 1));
                        buffers.push_back(boost::asio::buffer(&request.size, 4));
                        buffers.push_back(boost::asio::buffer(&out_message.uuid_to, 16));
                        buffers.push_back(boost::asio::buffer(&out_message.type, 1));
                        buffers.push_back(boost::asio::buffer(&out_message.size, 4));
                        boost::asio::write(s, buffers);
                        boost::asio::read(s, boost::asio::buffer(&response_header, sizeof response_header));

                        if (response_header.code == 1002 && response_header.size > 0) {
                            boost::asio::read(s, boost::asio::buffer(&sent_response, sizeof sent_response));
                            std::cout << "Symmetric key requested - " << sent_response.id << std::endl;
                        }

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

                        if (user_num < 0 || user_num > users.size()) {
                            std::cout << "no such user!" << std::endl;
                            break;
                        }

                        else if (!users[user_num].hasPublic) {
                            std::cout << "no public key for that user!" << std::endl;
                            break;
                        }
                        else {
                            // Generate new AES key
                            memset(users[user_num].symKey, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);

                            generate_key(reinterpret_cast<char*>(users[user_num].symKey), CryptoPP::AES::DEFAULT_KEYLENGTH);

                            users[user_num].hasSymm = true;

                            // Encrypt the symmetric key
                            std::string ciphertext;
                            CryptoPP::RSAES_OAEP_SHA_Encryptor sym_e(users[user_num].publicKey);
                            CryptoPP::StringSource symss(users[user_num].symKey, true, new CryptoPP::PK_EncryptorFilter(rng, sym_e, new CryptoPP::StringSink(ciphertext)));

                            request.code = 103;
                            request.size = 0;
                            out_message.size = 128;
                            out_message.type = 2;
                            out_message.uuid_to = users[user_num].uuid;

                            buffers.push_back(boost::asio::buffer(&request.clientId, user_id_length));
                            buffers.push_back(boost::asio::buffer(&request.version_, 1));
                            buffers.push_back(boost::asio::buffer(&request.code, 1));
                            buffers.push_back(boost::asio::buffer(&request.size, 4));
                            buffers.push_back(boost::asio::buffer(&out_message.uuid_to, 16));
                            buffers.push_back(boost::asio::buffer(&out_message.type, 1));
                            buffers.push_back(boost::asio::buffer(&out_message.size, 4));
                            buffers.push_back(boost::asio::buffer(&ciphertext, 16));
                            boost::asio::write(s, buffers);
                            boost::asio::read(s, boost::asio::buffer(&response_header, sizeof response_header));

                            if(response_header.code == 1003)
                                std::cout << "Symmetric key sent." << std::endl;
                        }

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
