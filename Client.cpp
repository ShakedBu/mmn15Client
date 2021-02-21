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
#include <immintrin.h>
#include <filters.h>
#include <aes.h>
#include <modes.h>
#include <osrng.h>

#include "structs.h"

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
        vector<User> users;

        // Files
        boost::filesystem::path userfile("me.info");
        ofstream myfile;
        ifstream myfile_i;

        // General variables
        vector<boost::asio::const_buffer> buffers;
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
        CryptoPP::byte messageb[max_length];

        // Waiting messages
        InMessageHeader in_message;

        // Keys
        PublicKeyResponse public_key;
        SymmKeyResponse symm_key;

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
        CryptoPP::RSAES_OAEP_SHA_Decryptor priv_d(privateKey);

        // AES
        CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];
        memset(iv, 0x00, CryptoPP::AES::BLOCKSIZE);

        string ciphertext;
        string plaintext;
        string decryptedtext;

        // Get instructions from user
        while (true) {
            memset(user, 0, sizeof user);
            memset(message, 0, sizeof message);
            memset(&request, 0, sizeof request);
            memset(&response_header, 0, sizeof response_header);
            memset(&users_list, 0, sizeof users_list);
            memset(&sent_response, 0, sizeof sent_response);
            memset(&messageb, 0, sizeof messageb);
            buffers.clear();
            action.clear();
            ciphertext.clear();
            plaintext.clear();
            decryptedtext.clear();
            request.version_ = 1;

            if (!uuid.is_nil())
                std::copy(uuid.begin(), uuid.end(), request.clientId);

            cout << endl << "MessageU client at your service! " << endl <<
                "1) Register" << endl <<
                "2) Request for client list" << endl <<
                "3) Request for public key" << endl <<
                "4) Request for waiting messages" << endl <<
                "5) Send a text message" << endl <<
                "51) Send a request for symmetric key" << endl <<
                "52) Send your semmetric key" << endl <<
                "0) Exit client" << endl;
            getline(cin, action);

            try
            {
                switch (stoi(action))
                {
                    case Exit:
                        s.close();
                        return 0;
                        break;

                    case Register:
                        // Check wether user is already registered
                        if (boost::filesystem::exists(userfile)){
                            cout << "file me.info already exsits." << endl;
                            break;
                        }

                        // Get user name and register user
                        cout << "Enter your name: ";
                        cin.getline(user, max_user_length);
                    
                        request.paylod = user;
                        request.code = 100;
                        request.size = strlen(user) + 160;
                        
                        // Send to server
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
                            myfile << user << endl << uuid_str << endl << buf;
                            myfile.close();

                            cout << "Registered!" << endl;
                        }
                        else {
                            cout << "Error registering" << endl;
                        }
                        break;

                    case ClientList:
                        if (!boost::filesystem::exists(userfile)) {
                            cout << "You need to register first." << endl;
                            break;
                        }

                        request.code = 101;
                        request.size = 0;

                        // Send to server
                        buffers.push_back(boost::asio::buffer(&request.clientId, user_id_length));
                        buffers.push_back(boost::asio::buffer(&request.version_, 1));
                        buffers.push_back(boost::asio::buffer(&request.code, 1));
                        buffers.push_back(boost::asio::buffer(&request.size, 4));
                        boost::asio::write(s, buffers);
                        boost::asio::read(s, boost::asio::buffer(&response_header, sizeof response_header));

                        if (response_header.code == 1001) {
                            user_num = response_header.size / (16 + 255);
                            cout << "Clients list:" << endl;
                            users.clear();

                            // Go over the clients and print them
                            for (size_t i = 0; i < user_num; i++)
                            {
                                // Get another client
                                boost::asio::read(s, boost::asio::buffer(&users_list, sizeof users_list));

                                User new_user;
                                new_user.uuid = users_list.uuid;
                                new_user.clientName = users_list.clientName;
                                new_user.hasPublic = false;
                                new_user.hasSymm = false;
                                users.push_back(new_user);

                                uuid_str = boost::uuids::to_string(new_user.uuid);
                                cout << (i+1) << ". " << uuid_str.c_str() << " " << new_user.clientName << endl;
                            }
                        }
                        else {
                            cout << "Error getting client list" << endl;
                        }

                        break;

                    case GetPublicKey:
                        if (!boost::filesystem::exists(userfile)) {
                            cout << "You need to register first." << endl;
                            break;
                        }

                        cout << "Whose public key would you like to request? (enter index)";
                        getline(cin, action);
                        user_num = stoi(action);
                        user_num -= 1;

                        if (user_num < 0 || user_num >= users.size()){
                            cout << "no such user!" << endl;
                            break;
                        }

                        if (users[user_num].hasPublic){
                            cout << "you already have this user's public key." << endl;
                            break;
                        }

                        request.code = 102;
                        request.size = 0;

                        // send to server
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
                        else {
                            cout << "Error getting public key" << endl;
                        }

                        break;

                    case WaitingMessages:
                        if (!boost::filesystem::exists(userfile)) {
                            cout << "You need to register first." << endl;
                            break;
                        }
                        request.code = 104;
                        request.size = 0;

                        // send to server
                        buffers.push_back(boost::asio::buffer(&request.clientId, user_id_length));
                        buffers.push_back(boost::asio::buffer(&request.version_, 1));
                        buffers.push_back(boost::asio::buffer(&request.code, 1));
                        buffers.push_back(boost::asio::buffer(&request.size, 4));
                        boost::asio::write(s, buffers);
                        boost::asio::read(s, boost::asio::buffer(&response_header, sizeof response_header));

                        if (response_header.code == 1004) {
                            int left = response_header.size;

                            cout << "Waiting messages: " << endl;

                            while (left > 0) {
                                // Go over messages.
                                boost::asio::read(s, boost::asio::buffer(&in_message, sizeof in_message));
                                int user_num;
                                for (size_t i = 0; i < users.size(); i++)
                                {
                                    if (users[i].uuid == in_message.uuid_from) {
                                        user_num = i;
                                        break;
                                    }
                                }                             

                                if (in_message.size > 0) {
                                    boost::asio::read(s, boost::asio::buffer(&messageb, in_message.size));
                                }

                                switch (in_message.type) {
                                    case 1:
                                        cout << "From: " << users[user_num].clientName << endl << "Request for symmetric key" << endl;
                                        break;
                                    case 2:
                                        {
                                            // Get other user's symmetric key
                                            CryptoPP::StringSource symmss(messageb, in_message.size, true, new CryptoPP::PK_DecryptorFilter(rng, priv_d, new CryptoPP::ArraySink(users[user_num].symKey, 16)));
                                            users[user_num].hasSymm = true;

                                            cout << "From: " << users[user_num].clientName << endl << "symmetric key received" << endl;
                                        }
                                        break;
                                    case 3:
                                        {
                                            if (users[user_num].hasSymm) {
                                                CryptoPP::AES::Decryption aesDecryption(users[user_num].symKey, CryptoPP::AES::DEFAULT_KEYLENGTH);
                                                CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);
                                                CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decryptedtext));
                                                stfDecryptor.Put(messageb, in_message.size);
                                                stfDecryptor.MessageEnd();

                                                cout << "From: " << users[user_num].clientName << endl << "Content:" << endl << decryptedtext << endl;
                                            }
                                            else {
                                                cout << "From: " << users[user_num].clientName << endl << "Content:" << endl << "No symmetric key" << endl;
                                            }
                                        }
                                        break;
                                }
                                left = left - sizeof in_message - in_message.size;
                            }
                        }
                        else {
                            cout << "Error reading messages" << endl;
                        }
                        break;

                    case SendTextMessage:
                        if (!boost::filesystem::exists(userfile)) {
                            cout << "You need to register first." << endl;
                            break;
                        }

                        cout << "To whom would you like to send a message? (enter index)";
                        getline(cin, action);
                        user_num = stoi(action);
                        user_num -= 1;

                        if (user_num < 0 || user_num >= users.size()) {
                            cout << "no such user!" << endl;
                            break;
                        }

                        if (!users[user_num].hasSymm) {
                            cout << "no symmetric key for that user!" << endl;
                            break;
                        }
                        else {
                            cout << "Enter the message to be sent: " << endl;
                            getline(cin, plaintext);

                            int size;

                            if (plaintext.length() % 16 == 0)
                                size = plaintext.length();
                            else if (plaintext.length() % 16 != 0)
                                size = plaintext.length() + 16 - (plaintext.length() % 128);

                            // Encrypt 
                            CryptoPP::byte cipherarray[1024];
                            CryptoPP::AES::Encryption aesEncryption(users[user_num].symKey, CryptoPP::AES::DEFAULT_KEYLENGTH);
                            CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);
                            CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::ArraySink(cipherarray, size));//StringSink(ciphertext));
                            stfEncryptor.Put(reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
                            stfEncryptor.MessageEnd();

                            request.code = 103;
                            request.size = sizeof out_message + ciphertext.size();
                            out_message.size = size;
                            out_message.type = 3;
                            out_message.uuid_to = users[user_num].uuid;

                            // send to server
                            buffers.push_back(boost::asio::buffer(&request.clientId, user_id_length));
                            buffers.push_back(boost::asio::buffer(&request.version_, 1));
                            buffers.push_back(boost::asio::buffer(&request.code, 1));
                            buffers.push_back(boost::asio::buffer(&request.size, 4));
                            buffers.push_back(boost::asio::buffer(&out_message.uuid_to, 16));
                            buffers.push_back(boost::asio::buffer(&out_message.type, 1));
                            buffers.push_back(boost::asio::buffer(&out_message.size, 4));
                            buffers.push_back(boost::asio::buffer(&cipherarray, size));
                            boost::asio::write(s, buffers);
                            boost::asio::read(s, boost::asio::buffer(&response_header, sizeof response_header));

                            if (response_header.code == 1003 && response_header.size > 0) {
                                // Read message id
                                boost::asio::read(s, boost::asio::buffer(&sent_response, sizeof sent_response));
                                cout << "Message sent - " << sent_response.id << endl;
                            }
                            else {
                                cout << "Error sending message" << endl;
                            }
                        }
                        break;

                    case RequestKey:
                        if (!boost::filesystem::exists(userfile)) {
                            cout << "You need to register first." << endl;
                            break;
                        }
                        cout << "From whom would you like to request a symmetric key? (enter index)";
                        getline(cin, action);
                        user_num = stoi(action);
                        user_num -= 1;

                        if (user_num < 0 || user_num >= users.size()) {
                            cout << "no such user!" << endl;
                            break;
                        }

                        request.code = 103;
                        request.size = sizeof out_message;
                        out_message.size = 0;
                        out_message.type = 1;
                        out_message.uuid_to = users[user_num].uuid;

                        // send to server
                        buffers.push_back(boost::asio::buffer(&request.clientId, user_id_length));
                        buffers.push_back(boost::asio::buffer(&request.version_, 1));
                        buffers.push_back(boost::asio::buffer(&request.code, 1));
                        buffers.push_back(boost::asio::buffer(&request.size, 4));
                        buffers.push_back(boost::asio::buffer(&out_message.uuid_to, 16));
                        buffers.push_back(boost::asio::buffer(&out_message.type, 1));
                        buffers.push_back(boost::asio::buffer(&out_message.size, 4));
                        boost::asio::write(s, buffers);
                        boost::asio::read(s, boost::asio::buffer(&response_header, sizeof response_header));

                        if (response_header.code == 1003 && response_header.size > 0) {
                            boost::asio::read(s, boost::asio::buffer(&sent_response, sizeof sent_response));
                            cout << "Symmetric key requested - " << sent_response.id << endl;
                        }
                        else {
                            cout << "Error requesting key" << endl;
                        }
                        break;

                    case SendKey:
                        if (!boost::filesystem::exists(userfile)) {
                            cout << "You need to register first." << endl;
                            break;
                        }
                        cout << "To whom would you like to send a symmetric key? (enter index)";
                        getline(cin, action);
                        user_num = stoi(action);
                        user_num -= 1;

                        if (user_num < 0 || user_num >= users.size()) {
                            cout << "no such user!" << endl;
                            break;
                        }

                        else if (!users[user_num].hasPublic) {
                            cout << "no public key for that user!" << endl;
                            break;
                        }
                        else {
                            // Generate new AES key if doesnt exists
                            if (!users[user_num].hasSymm) {
                                
                                memset(users[user_num].symKey, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
                                generate_key(reinterpret_cast<char*>(users[user_num].symKey), CryptoPP::AES::DEFAULT_KEYLENGTH);
                                users[user_num].hasSymm = true;
                            }

                            // Encrypt the symmetric key
                            CryptoPP::byte ciphersymm[128];
                            CryptoPP::RSAES_OAEP_SHA_Encryptor pub_e(users[user_num].publicKey);
                            CryptoPP::StringSource symss(users[user_num].symKey, CryptoPP::AES::DEFAULT_KEYLENGTH, true, new CryptoPP::PK_EncryptorFilter(rng, pub_e, new CryptoPP::ArraySink(ciphersymm, 128)));
                            
                            request.code = 103;
                            request.size = sizeof out_message + ciphertext.size();
                            out_message.size = 128;
                            out_message.type = 2;
                            out_message.uuid_to = users[user_num].uuid;

                            // send to server
                            buffers.push_back(boost::asio::buffer(&request.clientId, user_id_length));
                            buffers.push_back(boost::asio::buffer(&request.version_, 1));
                            buffers.push_back(boost::asio::buffer(&request.code, 1));
                            buffers.push_back(boost::asio::buffer(&request.size, 4));
                            buffers.push_back(boost::asio::buffer(&out_message.uuid_to, 16));
                            buffers.push_back(boost::asio::buffer(&out_message.type, 1));
                            buffers.push_back(boost::asio::buffer(&out_message.size, 4));
                            buffers.push_back(boost::asio::buffer(&ciphersymm, 128));
                            boost::asio::write(s, buffers);
                            boost::asio::read(s, boost::asio::buffer(&response_header, sizeof response_header));
                            
                            if (response_header.code == 1003) {
                                boost::asio::read(s, boost::asio::buffer(&sent_response, sizeof sent_response));
                                cout << "Symmetric key sent - " << sent_response.id << endl;
                            }
                            else {
                                cout << "Error sending key" << endl;
                            }
                        }
                        break;

                    default:
                        cout << "Please enter a valid number." << endl;
                        break;
                }
            }
            catch (exception& e){
                cerr << "server responded with an error" << endl << e.what() << endl;
            }
        }
    }
    catch (exception& e){
        cerr << "Error: " << e.what() << endl;
    }

    return 0;
}
