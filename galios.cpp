    //GF(2^128).
#include<iostream>
#include<fstream>
#include "GCM.h"
using std::string;


int main()
{
    srand(time(NULL)+33);
    vector<int>nonceS(16);
    for(int i=0;i<16;i++)
    {
        nonceS[i]=rand()%256;
    }
    vector<int>nonceR=nonceS;//send the nonce to the receiver.
    std::ifstream ifile;
    std::ofstream efile("encrypt.txt");
    ifile.open("text.txt");
    char c;
    std::string text;
    //first we encrypt the plaintext in CTR mode AES and use the encrypted text in GHASH.
    while (ifile.get(c))
    {
        text.push_back(c);
        if(text.size()==16){
            GCM obj(nonceS,true);
            efile<< obj.encrypt_message(text)<<std::endl; //GCTR(nonce,text)
            text.clear();
        }
    }
    if(!text.empty()){ 
        GCM obj(nonceS,true);
        efile << obj.encrypt_message(text);
        text.clear();
    }
    efile.close();

    ifile.close();
    ifile.open("encrypt.txt"); //was save in the encrypt.txt
    GCM obj(" "); //this is the secret key input already have in AES and it calculate the hash key h=E(k,0's).
    while(std::getline(ifile,text))
    {
        obj.GHASH(text);        
    }
    ifile.close();
    string Sender_GHASH=obj.MACS();
    std::cout<<"\nSender mac=" <<Sender_GHASH;
    //Now sender finishes with the GCTR and GHASH sends the (cipher,MAC).
    //AT RECEIVER.
    GCM rec(" ");//calculate the hash key.
    std::cout<<"\n----------------------------RECEIVER--------------------------";
    getchar();
    ifile.open("encrypt.txt");
    text="";
    while(std::getline(ifile,text)){ //calculate the GHASH for incoming cipher text.
        rec.GHASH(text); //calculate the GHAS and verifies the integrity by calculating the MAC.
    }
    ifile.close();
    if(rec.MACS()==Sender_GHASH){ //if true then proceed that no change in data.
        std::cout<<"\nMAC value matches. "<<rec.MACS()<<std::endl<<std::endl;
        ifile.open("encrypt.txt");
        text="";
        while(std::getline(ifile,text)){
            GCM obj(nonceR,true); //decrypt.
            std::cout<< obj.Decrypt_Message(text);
        }
        ifile.close();
    }else{
        std::cout<<"Reciver-mac="<<rec.MACS()<<std::endl;
        std::cout<<"The incoming message is discarded as MAC mismatch.";
    }
    return 0;
}
/*
Note:
    I have excluded the final GCTR(nonce,GHASH) . actually at final MAC =MSB(GCTR(nonce,GHASH)).
    I have done upto GHASH and took MSB 64 bit in practical it is send through the encryption with the beggining nonce without incrementer.
    AT receiver first receiver decrypt with its secret key and nonce between sender and receiver should be same after that it gets the sent
    MAC and calculate the GHASH from the cipher text if matches then it accept that cipher text and decrypt to get plain text using the same nonce
    and incrementer using CTR mod.
    Incrementer is done by adding one in nonce and is done in LSB(2^32) and rest is unaffected.
    because of the nonce the same plain text will have multiple cipher text yeilding high security.
    It supports low cost and parallelism than CCM as it don't use CMAC based on cipher chaining and multiply each of the block with hash key and
    lastly xoring the results.
    About the nonce scheme 
    it will have random bits upto 96 and 0's and 1.
*/