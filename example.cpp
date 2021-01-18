//
// Created by Roma on 07.01.2021.
//
#include <iostream>
#include <string>
#include "pm.h"

std::string ADD_STR = "add ";
std::string GET_STR = "get ";
std::string DEL_STR = "del ";
std::string CHK_STR = "chk ";
std::string MASTER_PASS_CHANGE = "master ";

int main(int argc, char *argv[]) {


    PasswordManager pm;
    pm.flagHandler(argc, argv);
    std::string in;

    do {
        if (pm.hasLogin) {
            getline(std::cin, in);
            using namespace std;
            cout << in << endl;
        }
        if (in == "q" or in == "exit" or in == "quit") {
            std::cout << "bye" << '\n';
            return 0;
        } else if (in == "h" or in == "help") {
            pm.printHelpMessage();
        } else {
            if (!pm.hasLogin) {
                pm.logIn();
            }
            if (in.find(ADD_STR) == 0) {
                std::string toAdd;
                toAdd = in.substr(ADD_STR.length());
                pm.addPassword(toAdd);
            }
            if (in.find(GET_STR) == 0) {
                std::string toGet;
                toGet = in.substr(GET_STR.length());
                pm.getPassword(toGet);
            }
            if (in.find(DEL_STR) == 0) {
                std::string toDel;
                toDel = in.substr(DEL_STR.length());
                pm.delPassword(toDel);
            }
            if (in.find(CHK_STR) == 0) {
                std::string toCheck;
                toCheck = in.substr(CHK_STR.length());
                pm.checkPassword(toCheck);
            }
            if (in.find(MASTER_PASS_CHANGE) == 0) {
                std::string toChange;
                toChange = in.substr(MASTER_PASS_CHANGE.length());
                using namespace std;
                cout << 123 << endl;
                pm.changeMasterPassword(toChange);
                cout << 123 << endl;
            }
        }
    } while (in != "exit" and in != "q" and in != "quit");


    return 0;
}