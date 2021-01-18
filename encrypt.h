#include <string>
#include <fstream>
#include "Windows.h"


std::string encode(const std::string &toEncode, const std::string &key) {
    std::string ABC_STRING = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+-*/=_!@#%:?(){};:<>[]`~";
    int len = ABC_STRING.length();
    string mes = toEncode, codeMes;
    int countRot = 0;
    for (auto i:mes) {
        if (i == ' ') codeMes.push_back(' ');
        if (ABC_STRING.find(i) != -1) {
            codeMes.push_back(ABC_STRING[(ABC_STRING.find(i) + ABC_STRING.find(key[countRot % key.size()])) % len]);
            countRot++;
        }
    }
    return codeMes;
}

std::string decode(const std::string &toDecode, const std::string &key) {
    std::string ABC_STRING = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+-*/=_!@#%:?(){};:<>[]`~";
    int len = ABC_STRING.length();
    string mes = toDecode, decodeMes;
    int countRot = 0;
    for (auto i:mes) {
        if (i == ' ') decodeMes.push_back(' ');
        if (ABC_STRING.find(i) != -1) {
            decodeMes.push_back(ABC_STRING[(ABC_STRING.find(i) - ABC_STRING.find(key[countRot % key.size()])) % len]);
            countRot++;
        }
    }
    return decodeMes;
}