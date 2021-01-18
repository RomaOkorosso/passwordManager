//
// Created by Roma on 17.01.2021.
//
#include <string>
#include <iostream>
#include <fstream>
#include "SHA256.h"
#include <utility>
#include <vector>
#include <winbase.h>
#include <winuser.h>
#include "encrypt.h"

#ifndef MAIN_CPP_PM_H
#define MAIN_CPP_PM_H

#include <cstring>
#include <fstream>
#include "SHA256.h"

const unsigned int SHA256::sha256_k[64] = //UL = uint32
        {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
         0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
         0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
         0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
         0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
         0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
         0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
         0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
         0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
         0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
         0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
         0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
         0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
         0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void SHA256::transform(const unsigned char *message, unsigned int block_nb) {
    uint32 w[64];
    uint32 wv[8];
    uint32 t1, t2;
    const unsigned char *sub_block;
    int i;
    int j;
    for (i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 6);
        for (j = 0; j < 16; j++) {
            SHA2_PACK32(&sub_block[j << 2], &w[j]);
        }
        for (j = 16; j < 64; j++) {
            w[j] = SHA256_F4(w[j - 2]) + w[j - 7] + SHA256_F3(w[j - 15]) + w[j - 16];
        }
        for (j = 0; j < 8; j++) {
            wv[j] = m_h[j];
        }
        for (j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6])
                 + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }
        for (j = 0; j < 8; j++) {
            m_h[j] += wv[j];
        }
    }
}

void SHA256::init() {
    m_h[0] = 0x6a09e667;
    m_h[1] = 0xbb67ae85;
    m_h[2] = 0x3c6ef372;
    m_h[3] = 0xa54ff53a;
    m_h[4] = 0x510e527f;
    m_h[5] = 0x9b05688c;
    m_h[6] = 0x1f83d9ab;
    m_h[7] = 0x5be0cd19;
    m_len = 0;
    m_tot_len = 0;
}

void SHA256::update(const unsigned char *message, unsigned int len) {
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len;
    const unsigned char *shifted_message;
    tmp_len = SHA224_256_BLOCK_SIZE - m_len;
    rem_len = len < tmp_len ? len : tmp_len;
    memcpy(&m_block[m_len], message, rem_len);
    if (m_len + len < SHA224_256_BLOCK_SIZE) {
        m_len += len;
        return;
    }
    new_len = len - rem_len;
    block_nb = new_len / SHA224_256_BLOCK_SIZE;
    shifted_message = message + rem_len;
    transform(m_block, 1);
    transform(shifted_message, block_nb);
    rem_len = new_len % SHA224_256_BLOCK_SIZE;
    memcpy(m_block, &shifted_message[block_nb << 6], rem_len);
    m_len = rem_len;
    m_tot_len += (block_nb + 1) << 6;
}

void SHA256::final(unsigned char *digest) {
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;
    int i;
    block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9)
                     < (m_len % SHA224_256_BLOCK_SIZE)));
    len_b = (m_tot_len + m_len) << 3;
    pm_len = block_nb << 6;
    memset(m_block + m_len, 0, pm_len - m_len);
    m_block[m_len] = 0x80;
    SHA2_UNPACK32(len_b, m_block + pm_len - 4);
    transform(m_block, block_nb);
    for (i = 0; i < 8; i++) {
        SHA2_UNPACK32(m_h[i], &digest[i << 2]);
    }
}

std::string sha256(std::string input) {
    unsigned char digest[SHA256::DIGEST_SIZE];
    memset(digest, 0, SHA256::DIGEST_SIZE);

    SHA256 ctx = SHA256();
    ctx.init();
    ctx.update((unsigned char *) input.c_str(), input.length());
    ctx.final(digest);

    char buf[2 * SHA256::DIGEST_SIZE + 1];
    buf[2 * SHA256::DIGEST_SIZE] = 0;
    for (int i = 0; i < SHA256::DIGEST_SIZE; i++)
        sprintf(buf + i * 2, "%02x", digest[i]);
    return std::string(buf);
}


struct PasswordManager {

    std::string path = "path.txt";
    std::string pathToMasterPass = "masterPass.txt";
    bool hasLogin = false;
    std::string masterPass = getMasterPass();

public:

    static std::string mainHash(std::string str) {
        std::string a = "asdf";
        std::string output = sha256("");
        return output;
    }

    void logIn() {
        std::cout << "Please enter master password\n";
        std::string passToCheck;
        char tmp;
        do {
            tmp = std::cin.get();
            if (tmp != '\n') {
                passToCheck += tmp;
            }
        } while (tmp != '\n');
        std::cout << "master pass to check is: " << passToCheck << '\n';

        std::string toCheck = mainHash(passToCheck);
        std::cout << toCheck << '\n';
        std::string pass;
        if (isFileExists(pathToMasterPass))
            pass = getMasterPass();
        else {
            createFile(pathToMasterPass);
            std::ofstream fout(pathToMasterPass);
            fout << toCheck;
            hasLogin = true;
        }

        if (toCheck == pass) {
            std::cout << "Success!\n";
            hasLogin = true;
        } else if (pass.empty()) {
            std::ofstream fout(pathToMasterPass);
            fout << toCheck;
            std::cout << "Master pass file is empty -> Success!\n";
            hasLogin = true;
        } else {
            std::cout << "Error. Wrong password\n";
            exit(0);
        }
    }

    void addPassword(const std::string &toAdd) {
        std::vector<std::string> siteLoginPassVec;
        parserSiteLoginPass(siteLoginPassVec, toAdd);
        if (!empty(siteLoginPassVec)) {
            std::string siteLogin = siteLoginPassVec[0];
            std::string newPass = siteLoginPassVec[1];
            std::vector<std::string> siteLoginVec = getSiteAndLogin(siteLogin);
            std::string oldPass = getEncryptedPassword(siteLoginVec[0], siteLoginVec[1]);

            std::string pathToPass = getPathToPass();

            if (!isFileExists(pathToPass))
                createFile(pathToPass);

            std::ifstream fin(pathToPass);

            newPass = encode(newPass, masterPass);
            std::cout << "old password: " << oldPass << "\n";
            std::cout << "new password: " << newPass << '\n';
            if (oldPass != "-1") {
                std::string replaceStrFromFile = readWholeFile(pathToPass);
                std::cout << "replaceStrFromFile:\n" << replaceStrFromFile << '\n';
                int left = replaceStrFromFile.find(oldPass);
                newPass.insert(0, 1, ' ');
                int len = lenComp(newPass, oldPass);

                replaceStrFromFile.replace(left, len, newPass);
                fin.close();
                std::ofstream fout(pathToPass);
                std::cout << "Password for " << siteLogin << " has been changed\n";
            } else {
                fin.close();
                std::ofstream out(pathToPass, std::ios::app);
                newPass += '\n';
                out << siteLogin << ' ' << newPass;
                std::cout << "Password for " << siteLogin << " has been added\n";
            }
        }
    }

    void delPassword(const std::string &siteLoginPassToDel) {

        if (siteLoginPassToDel.find(':') == -1) {
            std::cout << "Site and login must be separated by ':' character, pls try again\n";
        } else {
            std::string fullFile = readWholeFile(getPathToPass());
            int left = fullFile.find(siteLoginPassToDel);

            if (left != -1) {
                std::vector<std::string> siteLoginVec = getSiteAndLogin(siteLoginPassToDel);
                std::string encPass = getEncryptedPassword(siteLoginVec[0], siteLoginVec[1]);
                std::string fullStr = siteLoginPassToDel + ' ' + encPass + '\n';
                int len = fullStr.length();
                fullFile.replace(left, len, "");
                overwriteFile(getPathToPass(), fullFile);
                std::cout << "Password and site:login pair were successfully deleted\n";
            } else {
                std::cout << "Has no this site:login pass recording in file with passwords\n";
            }
        }

    }

    void getPassword(const std::string &siteLoginStr) {
        std::vector<std::string> siteLoginVec = getSiteAndLogin(siteLoginStr);
        std::string encryptedPass = getEncryptedPassword(siteLoginVec[0], siteLoginVec[1]);
        copyDataToClipboard(decode(encryptedPass, masterPass));
    }

    void flagHandler(int argc, char *argv[]) {
        /* Handler flags from start from command line or termenal
        */
        using namespace std;
        for (int i = 0; i < argc; i++) {
            string s(argv[i]);
            if (s == "--help" or s == "help" or s == "h") {
                printHelpMessage();
            }

            if (s == "config" or s == "--config" or s == "c") {
                string fullStr;
                for (int j = i; j < argc; j++) {
                    fullStr += string(argv[j]);
                }
                if (fullStr.find("get") == -1) {
                    i++;
                    // TODO rewrite to edit path file
                    path = argv[i];
                } else {
                    vector<string> siteAndLogin;
                    siteAndLogin = getSiteAndLogin(fullStr);
                    string password = getEncryptedPassword(siteAndLogin[0], siteAndLogin[1]);
                    if (password == "-1")
                        cout << "Have no any same site login pair\n";
                    else {
                        copyDataToClipboard(password);
                    }
                }
            }
        }
    }

    void checkPassword(const std::string &siteLoginPassStr) {
        std::string fullStr = readWholeFile(getPathToPass());
        int left = fullStr.find(siteLoginPassStr);

        if (left != -1) {
            std::vector<std::string> siteLoginVec = getSiteAndLogin(siteLoginPassStr);
            std::string encPass = getEncryptedPassword(siteLoginVec[0], siteLoginVec[1]);
            std::string fullStr = siteLoginPassStr + ' ' + encPass + '\n';
        }
        if (fullStr.find(siteLoginPassStr) != -1)
            std::cout << "Site:login password in file!\n";
        else
            std::cout << "Site:login password not in file!\n";
    }

    void changeMasterPassword(std::string &newPassword) {
        std::string newHashedPass = mainHash(newPassword);
        fullRefresh(masterPass, newHashedPass);
        overwriteFile(pathToMasterPass, newHashedPass);
        masterPass = newHashedPass;
        std::cout << "Master password has been changed!\n";
    }

    void printHelpMessage() {
        std::cout << HELP_TEXT;
    }

private:

    // BELOW IS WORKABLE METHODS
    std::string HELP_TEXT = "usage: ./pm.exe [options]\n--help\t\t: help information\n--config [path]\t\t:"\
                    "run program with config database"\
                    "\nmaster\t\t: set new master password\n"\
                    "get SITE:LOGIN\t\t: get password to the clipboard\nadd SITE:LOGIN <password>\t:"\
                    "add to the database password\n"\
                    "del SITE:LOGIN\t\t: delete from database password for SITE and LOGIN\nchk SITE:LOGIN\t\t: "\
                    "check existence of password for SITE LOGIN\n"\
                    "exit/q/quit\t\t: exit from program\n";

    std::string getPathToPass() const {
        std::ifstream fin(path);
        std::string pathToPass;
        getline(fin, pathToPass);

        return pathToPass;
    }

    void fullRefresh(const std::string &oldPass, const std::string &newPass) {
        // oldPass and newPass must be hashed

        std::string fullFile = readWholeFile(getPathToPass());
        int left = fullFile.find(' ');
        int right = fullFile.find('\n', left);
        while (left != -1) {
            std::string encPass = fullFile.substr(left, right);
            std::string decPass = decode(encPass, oldPass);
            std::string newEncPass = encode(decPass, newPass);
            int len = lenComp(encPass, newEncPass);
            fullFile.replace(left, right - 1, newEncPass);
            left = fullFile.find(' ', left + 1);
            if (left != -1)
                right = fullFile.find('\n', left);
        }
        overwriteFile(getPathToPass(), fullFile);
    }

    static int lenComp(const std::string &first, const std::string &second) {
        int len;
        if (first.length() < second.length())
            len = first.length();
        else
            len = second.length();
        return len;
    }

    void editPathToPass(const std::string &newPath) const {
        std::ofstream fout(path, std::ios::trunc);
        fout << newPath;
        fout.close();
    }

    static void overwriteFile(const std::string &filePath, const std::string &newFilling) {
        std::ofstream fout(filePath, std::ios::trunc);
        fout << newFilling;
        fout.close();
    }

    std::string getMasterPass() {
        std::ifstream fin(pathToMasterPass);
        std::string masterPassToReturn;
        getline(fin, masterPassToReturn);

        return masterPassToReturn;
    }

    std::string getEncryptedPassword(const std::string &site, const std::string &login) {
        using namespace std;
        ifstream fin(getPathToPass());
        if (!fin) {
            cout << "Cannot find file, try again!\n";
        }
        string tmp;
        while (!fin.eof()) {
            getline(fin, tmp);
            if (tmp.find(site) != -1 and tmp.find(login) != -1) {
                int left = tmp.find(' ');
                string password = tmp.substr(left + 1, tmp.length() - 1);
                return password;
            }
        }
        return "-1";
    }

    static std::string readWholeFile(const std::string &filename) {
        std::ifstream fin(filename);
        std::string toReturn((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
        fin.close();
        return toReturn;
    }

    static void parserSiteLoginPass(std::vector<std::string> &siteLoginAndPassVec, const std::string &toParse) {
        std::vector<std::string> toReturn;

        if (toParse.find(':') == -1) {
            std::cout << "Site and login must be separated by ':' character, pls try again\n";
        } else if (toParse.find(' ') == -1) {
            std::cout << "Site:Login pair and password must be separated by whitespace, pls try again\n";
        } else {
            int left = toParse.find(' ');
            unsigned int len = toParse.length() - 1;
            siteLoginAndPassVec.push_back(toParse.substr(0, left));
            siteLoginAndPassVec.push_back(toParse.substr(left + 1, len));
            std::cout << "parse success\n";
//            cout << "Parse success\nSite and login: " << siteLoginAndPassVec[0] << "\npass: " << siteLoginAndPassVec[1]
//                 << '\n';
        }
    }

    static void copyDataToClipboard(const std::string &password) {
        if (!OpenClipboard((HWND) nullptr)) {
            perror("OpenClipboard");
            system("pause");
            exit(1);
        }
        EmptyClipboard();
        HGLOBAL hglb = GlobalAlloc(GMEM_MOVEABLE, strlen(password.c_str()) + 1);
        if (hglb == nullptr) {
            perror("GlobalAlloc");
            CloseClipboard();
            system("pause");
            exit(1);
        }
        char *pBuf = (char *) GlobalLock(hglb);
        strcpy(pBuf, password.c_str());
        GlobalUnlock(hglb);
        SetClipboardData(CF_OEMTEXT, hglb);
        CloseClipboard();
        std::cout << "Password has been copied to clipboard and ready to paste\n";
    }

    static inline bool isFileExists(const std::string &name) {
        std::ifstream f(name.c_str());
        return f.good();
    }

    static void createFile(const std::string &pathToCreate, const std::string &fileNameToCreate = "") {
        std::string fullName;
        if (fileNameToCreate.empty())
            fullName = pathToCreate;
        else
            fullName = pathToCreate + fileNameToCreate;
        if (!isFileExists(fullName)) {
            std::ofstream fout(fullName);
            fout.close();
        }
    }

    static std::vector<std::string> getSiteAndLogin(const std::string &toParse, const std::string &delimiter = ":") {
        std::vector<std::string> toReturn;

        int left = toParse.find(delimiter);
        toReturn.push_back(toParse.substr(0, left));
        toReturn.push_back(toParse.substr(left + 1, toParse.length() - 1));
        // std::cout << "Site: " << toReturn[0] << "\nLogin: " << toReturn[1] << '\n';

        return toReturn;
    }
};


#endif //MAIN_CPP_PM_H
