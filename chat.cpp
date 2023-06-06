#include "chat.h"

Chat::Chat() {
    data_count = 0;
}

void Chat::reg(char _login[LOGINLENGTH], char _pass[], int pass_length) {
    uint hash = hash_multiply(_login, LOGINLENGTH) % HASH_TABLE_SIZE;
    uint probes = 0;

    while (probes < MAX_PROBES) {
        if(data[hash].login[0] == '\0') {
            // найдена пустая ячейка - добавляем элемент
            uint* pass_sha1_hash = sha1(_pass, pass_length);
            AuthData new_data(_login, pass_sha1_hash);

            data[hash] = new_data;
            ++data_count;

            return;
        } else if(strcmp(_login, data[hash].login) == 0) {
            // элемент с таким логином уже есть - заменяем хеш пароля на новый
            uint* pass_sha1_hash = sha1(_pass, pass_length);
            memcpy(data[hash].pass_sha1_hash, pass_sha1_hash, SHA1HASHLENGTHBYTES);
            delete[] pass_sha1_hash;

            return;
        } else {
            // пробуем следующую ячейку
            ++probes;
            hash = (hash + probes * probes) % HASH_TABLE_SIZE;
        }
    }

    throw std::overflow_error("Hash table is full, cannot add new element!");
}

bool Chat::login(char _login[LOGINLENGTH], char _pass[], int pass_length) {
    uint hash = hash_multiply(_login, LOGINLENGTH) % HASH_TABLE_SIZE;
    uint probes = 0;

    while (probes < MAX_PROBES) {
        if(data[hash].login[0] == '\0') {
            // элемент не найден
            return false;
        } else if(strcmp(_login, data[hash].login) == 0) {
            // элемент найден - проверяем пароль
            uint* pass_sha1_hash = sha1(_pass, pass_length);
            bool result = memcmp(pass_sha1_hash, data[hash].pass_sha1_hash, SHA1HASHLENGTHBYTES) == 0;
            delete[] pass_sha1_hash;

            return result;
        } else {
            // пробуем следующую ячейку
            ++probes;
            hash = (hash + probes * probes) % HASH_TABLE_SIZE;
        }
    }

    return false;
}

uint Chat::hash_multiply(char* s, int len) {
    const uint A = 2654435769; // Константа для метода умножения
    uint h = 0;

    for(int i = 0; i < len; ++i) {
        h += s[i];
        h *= A;
    }

    return h;
}
