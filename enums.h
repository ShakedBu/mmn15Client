#pragma once

enum {
    max_length = 2048,
    max_user_length = 255,
    user_id_length = 16,
    max_clients = 7,
    max_messages = 10,
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
enum ResponseCode {
    fail = 9000
};
