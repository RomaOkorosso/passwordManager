#include <string>
#include <fstream>
#include "Windows.h"

const std::string ABC_STRING = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+-*/=_!@#%:?(){};:<>[]`~";

std::string encode(const std::string &toEncode, const std::string &key) {

    int len = ABC_STRING.length();
    string mes = toEncode, codeMes;
    int count_rot = 0;
    for (auto i:mes) {
        if (i == ' ') codeMes.push_back(' ');
        if (ABC_STRING.find(i) != -1) {
            codeMes.push_back(ABC_STRING[(ABC_STRING.find(i) + ABC_STRING.find(key[count_rot % key.size()])) % len]);
            count_rot++;
        }
    }
    return codeMes;
}

std::string decode(const std::string &toDecode, const std::string &key) {
    int len = ABC_STRING.length();
    string mes = toDecode, decodeMes;
    int count_rot = 0;
    for (auto i:mes) {
        if (i == ' ') decodeMes.push_back(' ');
        if (ABC_STRING.find(i) != -1) {
            decodeMes.push_back(ABC_STRING[(ABC_STRING.find(i) - ABC_STRING.find(key[count_rot % key.size()])) % len]);
            count_rot++;
        }
    }
    return decodeMes;
}