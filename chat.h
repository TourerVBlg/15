#pragma once

#include "../headers/sha1.h"
#include <string.h>

#define SIZE 10
#define LOGINLENGTH 10

class Chat {
public:
    Chat();
    void reg(char _login[LOGINLENGTH], char _pass[], int pass_length);
    bool login(char _login[LOGINLENGTH], char _pass[], int pass_length);

private:
    struct AuthData {
        AuthData():
                login(""),
                pass_sha1_hash(nullptr) {
        }
        ~AuthData() {
            if (pass_sha1_hash != nullptr)
                delete[] pass_sha1_hash;
        }
        AuthData(char _login[LOGINLENGTH], uint* sh1) {
            strcpy(login, _login);
            pass_sha1_hash = new uint[SHA1HASHLENGTHUINTS];
            memcpy(pass_sha1_hash, sh1, SHA1HASHLENGTHBYTES);
        }

        char login[LOGINLENGTH];
        uint* pass_sha1_hash;
    };

    uint hash_multiply(char* s, int len);

    AuthData data[SIZE];
    int data_count;

    const uint HASH_TABLE_SIZE = 13;
    const uint MAX_PROBES = 5;
};
