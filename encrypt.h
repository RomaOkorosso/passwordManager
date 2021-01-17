//
// Created by Roma on 07.01.2021.
//
#include <string>
#include <cstring>
#include <algorithm>

#define N 256

#ifndef MAIN_CPP_ENCRYPT_H
#define MAIN_CPP_ENCRYPT_H

struct RC4 {
    void swap(char *a, char *b) {
        int tmp = *a;
        *a = *b;
        *b = tmp;
    }

    int KSA(std::string key, std::string &S) {
        int len = key.length();
        int j = 0;
        for (int i = 0; i < N; i++)
            S[i] = i;

        for (int i = 0; i < N; i++) {
            j = (j + (int) S[i] + key[i % len]) % N;
            swap(&S[i], &S[j]);
        }
        return 0;
    }

    int PRGA(std::string &S, std::string plaintext, std::string &ciphertext) {
        int i = 0;
        int j = 0;

        for (size_t n = 0, len = plaintext.length(); n < len; n++) {
            i = (i + 1) % N;
            j = (j + S[i]) % N;
            swap(&S[i], &S[j]);
            int rnd = S[(S[i] + S[j]) % N];
            ciphertext[n] = rnd ^ plaintext[n];
        }

        return 0;
    }

    void fixNewLine(std::string &S){
        int left = S.find('\n');
        while (left != -1){
            S.replace(left, 1, "BAN");
            left = S.find('\n', left);
        }
    }

    std::string genRC4(std::string key, std::string plaintext, std::string ciphertext) {

        std::string S(N, ' ');
        KSA(key, S);

        PRGA(S, plaintext, ciphertext);
        cout << S << '\n';
        // fixNewLine(S);
        cout << '\n' << S << '\n';

        for (int i = 0; i < S.length(); i++){

        }

        return S;
        //ciphertext
        // return 0;
    }
};

#endif //MAIN_CPP_ENCRYPT_H
