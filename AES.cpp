#include<iostream>
#include"AES.h"

int main()
{
    string text="I love crypto.";
    string key=" ";
    Encryption obj(text);
    std::string cipher=obj.encrypt_message();
    std::cout<<cipher<<std::endl;
    
    Decryption D(cipher);
    std::string plaintext=D.decrypt_message();
    std::cout<<"\n"<<plaintext;
    return 0;
}