#pragma once
#include <boost/archive/binary_oarchive.hpp>
#include <boost/serialization/serialization.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/asio.hpp>
#include <iostream>

#include "enums.h"

struct Request {
    char clientId[user_id_length];
    uint8_t version_ = 1;
    uint8_t code;
    uint32_t size;
    std::string paylod;
};
struct ResponseHeader {
    int8_t version;
    int16_t code;
    unsigned int size;
};
struct RegisterResponse {
    boost::uuids::uuid uuid;
};
struct UsersResponse {
    boost::uuids::uuid uuid;
    char clientName[max_user_length];
};
struct SentResponse {
    boost::uuids::uuid uuid;
    unsigned int id;
};
struct OutMessage {
    boost::uuids::uuid uuid_to;
    char type;
    unsigned int size;
    std::string content;
};
struct InMessageHeader {
    boost::uuids::uuid uuid_from;
    unsigned int id;
    char type;
    unsigned int size;
};
struct User {
    boost::uuids::uuid uuid;
    std::string clientName;
    char publicKey[32];
    char symKey;
};
struct PublicKeyResponse {
    boost::uuids::uuid uuid;
    char publicKey[32];
};