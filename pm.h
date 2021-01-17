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

#ifndef MAIN_CPP_PM_H
#define MAIN_CPP_PM_H


struct PasswordManager {
    std::string path = "path.txt";
    std::string pathToMasterPass = "masterPass.txt";
    bool isLog = false;

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
            isLog = true;
        }

        if (toCheck == pass) {
            cout << "Success!\n";
            isLog = true;
        } else if (pass.empty()) {
            ofstream fout(pathToMasterPass);
            fout << toCheck;
            cout << "Master pass file is empty -> Success!\n";
            isLog = true;
        } else {
            cout << "old mp: " << pass << '\n';
            cout << "pass to check is: " << toCheck << '\n';
            cout << "Error. Wrong password\n";
        }
    }

    void addPassword(const std::string &toAdd) {
        std::vector<std::string> siteLoginPassVec;
        parserSiteLoginPass(siteLoginPassVec, toAdd);
        std::string siteLogin = siteLoginPassVec[0];
        std::string pass = siteLoginPassVec[1];
        std::vector<std::string> siteLoginVec = getSiteAndLogin(siteLogin);
        std::string password = getPassword(siteLoginVec[0], siteLoginVec[1]);
        cout << "password: " << password << "\n";
        std::string pathToPass = getPathToPass();

        if (!isFileExists(pathToPass))
            createFile(pathToPass);

        ifstream fin(pathToPass);

        // TODO add encode pass
        if (password != "-1") {
            std::string replaceStrFromFile = readWholeFile(pathToPass);
            cout << "replaceStrFromFile: " << replaceStrFromFile << '\n';
            int left = replaceStrFromFile.find(password);
            int len = replaceStrFromFile.length() - 1;
            replaceStrFromFile.replace(left, len, pass);
            fin.close();
            ofstream fout(pathToPass);
            fout << replaceStrFromFile;
            cout << "Password for " << siteLogin << " has been changed\n";
        } else {
            fin.close();
            ofstream out(pathToPass, ios::app);
            out << siteLogin << ' ' << pass << '\n';
            cout << "Password for " << siteLogin << " has been added\n";
        }

    }

    std::string delPassword(const std::string &site, const std::string &login, const std::string &pass) {

    }

    std::string getPassword(const std::string &site, const std::string &login) {
        using namespace std;
        ifstream fin(getPathToPass());
        if (!fin) {
            cout << "Cannot find file, try again!\n";
        }
        string tmp;
        bool flag = false;
        while (!fin.eof()) {
            getline(fin, tmp);
            cout << "test: " << tmp << '\n';
            if (tmp.find(site) != -1 and tmp.find(login) != -1) {
                cout << "tmp: " << tmp << '\n';
                int left = tmp.find(' ');
                string password = tmp.substr(left, tmp.length() - 1);
                return password;
            }
        }
        return "-1";
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
                    string password = getPassword(siteAndLogin[0], siteAndLogin[1]);
                    if (password == "-1")
                        cout << "Have no any same site login pair\n";
                    else {
                        copyDataToClipboard(password);
                    }
                }
            }
        }
    }


    void printHelpMessage() {
        cout << HELP_TEXT;
    }

private:

    static std::string readWholeFile(const std::string &filename) {
        std::string toReturn;
        ifstream fin(filename);
        while (!fin.eof()) {
            std::string tmp;
            getline(fin, tmp);
            toReturn.assign(tmp);
        }
        return toReturn;
    }

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

    std::string getMasterPass() {
        ifstream fin(pathToMasterPass);
        std::string masterPass;
        getline(fin, masterPass);

        return masterPass;
    }

    static void parserSiteLoginPass(std::vector<std::string> &siteLoginAndPassVec, const std::string &toParse) {
        std::vector<std::string> toReturn;

        if (toParse.find(':') == -1) {
            std::cout << "Site and login must be separated by ':' character, pls try again\n";
        } else if (toParse.find(' ') == -1) {
            std::cout << "Site:Login pair and password must be separated by whitespace, pls try again\n";
        } else {
            int left = toParse.find(' ');
            int len = toParse.length() - 1;
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

// ConstraintBuilder(
//      (parent <- view).padding(8),
//      (view -> parent).padding(8),
//      view ^ parent,
//      view . parent
//      ).activate()
//
//enum ConstraintType {
//    case leading
//    case trailing
//    case top
//    case bottom
//    case center
//};
//
//operator <- (lhs: UIView, rhs: UIView) -> Constraint {
//    Constraint(lhs, rhs, constraintType: .leading)
//}
//
//operator -> (lhs: UIView, rhs: UIView) -> Constraint {
//    Constraint(lhs, rhs, constraintType: .trailing)
//}
//
//operator ^ (lhs: UIView, rhs: UIView) -> Constraint {
//    Constraint(lhs, rhs, constraintType: .top)
//}
//
//operator . (lhs: UIView, rhs: UIView) -> Constraint {
//    Constraint(lhs, rhs, constraintType: .bottom)
//}
//
//
//class Constraint {
//    var view1, view2: UIView
//    var padding: CGFloat
//    var constraintType: ConstraintType
//
//    func padding(_ padding: Int) -> Constraint {
//        self.padding = padding
//        return self
//    }
//
//    func buildConstraint() -> NSLayoutConstraint {
//        var constraint: NSLayoutConstraint
//        switch constraintType {
//            case .leading:
//                constraint = view2.leadingAnchor.constraint(view2.leadingAnchor, constant: padding)
//            case .trailing:
//                constraint = view1.trailingAnchor.constraint(view2.trailingAnchor, constant: padding)
//            case .top:
//                constraint = view1.topAnchor.constraint(view2.topAnchor, constant: padding)
//            case .trailing:
//                constraint = view1.bottomAnchor.constraint(view2.bottomAnchor, constant: padding)
//            }
//        return constraint
//    }
//
//    init(_ view1: UIView, _ view2: UIView, constraintType: ConstraintType, _ padding: CGFloat = 0) {
//        self.view1 = view1
//        self.view2 = view2
//        self.padding = padding
//        self.constraintType = constraintType
//    }
//}
//
//class ConstraintBuilder {
//
//    let constraints: [Constraint]
//
//    func activate() {
//        NSLayoutConstraint.activate(constraints.map { $0.buildConstraint() })
//    }
//
//    init(_
//    constraints: Constraint
//    ...) {
//        self.constraints = constraint
//    }
//
//}

#endif //MAIN_CPP_PM_H
