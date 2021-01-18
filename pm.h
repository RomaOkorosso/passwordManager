//
// Created by Roma on 17.01.2021.
//
#include <string>
#include <iostream>
#include <fstream>
#include "sha256.h"
#include <vector>
#include <winbase.h>
#include <winuser.h>
#include "encrypt.h"

#ifndef MAIN_CPP_PM_H
#define MAIN_CPP_PM_H


struct PasswordManager {

    std::string path = "path.txt";
    std::string pathToMasterPass = "masterPass.txt";
    bool hasLogin = false;
    std::string masterPass = getMasterPass();

public:

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
            ofstream fout(pathToMasterPass);
            fout << toCheck;
            hasLogin = true;
        }

        if (toCheck == pass) {
            cout << "Success!\n";
            hasLogin = true;
        } else if (pass.empty()) {
            ofstream fout(pathToMasterPass);
            fout << toCheck;
            cout << "Master pass file is empty -> Success!\n";
            hasLogin = true;
        } else {
            cout << "Error. Wrong password\n";
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

            ifstream fin(pathToPass);

            newPass = encode(newPass, masterPass);
            cout << "old password: " << oldPass << "\n";
            cout << "new password: " << newPass << '\n';
            if (oldPass != "-1") {
                std::string replaceStrFromFile = readWholeFile(pathToPass);
                cout << "replaceStrFromFile:\n" << replaceStrFromFile << '\n';
                int left = replaceStrFromFile.find(oldPass);
                newPass.insert(0, 1, ' ');
                int len = lenComp(newPass, oldPass);

                replaceStrFromFile.replace(left, len, newPass);
                fin.close();
                ofstream fout(pathToPass);
                cout << "Password for " << siteLogin << " has been changed\n";
            } else {
                fin.close();
                ofstream out(pathToPass, ios::app);
                newPass += '\n';
                out << siteLogin << ' ' << newPass;
                cout << "Password for " << siteLogin << " has been added\n";
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
                cout << "Password and site:login pair were successfully deleted\n";
            } else {
                cout << "Has no this site:login pass recording in file with passwords\n";
            }
        }

    }

    void getPassword(const std::string &siteLoginStr) {
        std::vector<string> siteLoginVec = getSiteAndLogin(siteLoginStr);
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
            cout << "Site:login password in file!\n";
        else
            cout << "Site:login password not in file!\n";
    }

    void changeMasterPassword(std::string &newPassword) {
        std::string newHashedPass = mainHash(newPassword);
        fullRefresh(masterPass, newHashedPass);
        overwriteFile(pathToMasterPass, newHashedPass);
        masterPass = newHashedPass;
        cout << "Master password has been changed!\n";
    }

    void printHelpMessage() {
        cout << HELP_TEXT;
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

    std::string getPathToPass() {
        ifstream fin(path);
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
            left = fullFile.find(' ');
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
        ofstream fout(path, ios::trunc);
        fout << newPath;
        fout.close();
    }

    static void overwriteFile(const std::string &filePath, const std::string &newFilling) {
        ofstream fout(filePath, ios::trunc);
        fout << newFilling;
        fout.close();
    }

    std::string getMasterPass() {
        ifstream fin(pathToMasterPass);
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
        ifstream fin(filename);
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
            cout << "parse success\n";
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
            ofstream fout(fullName);
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
