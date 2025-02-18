#ifndef Deffie
#include<iostream>
#include<time.h>
#include<vector>
#include<unordered_map>
using std::string,std::vector;
#define Deffie

/*
    p=10061,g=3;
key exchange algorithm
. basic idea is generate the random number(local machine) for each user's its a private key for that user's 
. now find the public key prime 10061 and primitive root(generator)3 is selected this can be very large in real world now for each user
    we found public key as g^(PR) mod p PR is corresponding private keys.
. Actually this public key information is send to the user which want to transfer message for eg A can have public key of B and viceversa
. Now as we are dealing with the symmetric cipher its a method of transfering the shared key in unsecured channel so to generate the shared key 
    the user uses (PU)^PR mod p where PU is the public that if A want to communicate with B A uses B's public key power its private key to find shared
    key. The data is encrypted with this shared key now B opens the encrypted message by using A's public key power its private key
    the result for (PU.B)^PR mod p== (PU.A)^PR mod p and hence the same key is used for encryption and decryption .
So this is all about the Deffie_Helman process.

I am assuming AES encryption algorithm(128) so i will be simulating how shared key are generated 
I am using the hex value so i need to generate 32 values from 0-15 or 16 values from (0-255) so 32 random numbers i will have 3 users.
and the txt file will act as a virtual machine where i save the private and public key.
*/
int Modular_Exponential(int p,int g,int m) //repeatitive squaring using binary exponential technique.
{
    int bits=31-__builtin_clz(m); //how may bits for m.
    int d=1;
    for(int i=bits;i>=0;i--)
    {
        d=(d*d)%p;
        if((m >>i) &1) d=(d*g)%p;
    }
    return d;
}
class Deffie_Helman
{
private:
    int p=10061,g=3; //defult i choose it but this information can send by the users for eg A can send this information to B,C 
    std::unordered_map<int,string>dectohex={ //mapping of dec to hex
        {0,"0"},
        {1,"1"},
        {2,"2"},
        {3,"3"},
        {4,"4"},
        {5,"5"},
        {6,"6"},
        {7,"7"},
        {8,"8"},
        {9,"9"},
        {10,"A"},
        {11,"B"},
        {12,"C"},
        {13,"D"},
        {14,"E"},
        {15,"F"}
    };
public:
    Deffie_Helman(){
        srand(time(NULL)); //seed.
    }
    vector<int>Generate_PrivateKey();
    vector<int>Calculate_PublicKey(vector<int>);
    string shared_key(vector<int>,vector<int>);//as i have use data type string to take the key and convert to hex.
};
vector<int> Deffie_Helman::Generate_PrivateKey()
{
    //it generate random number from 200 to 10061. as 1 to 200 a small number anyway % 16 is performed in last i am using hex 4 bit so 0-15
    int lower_bound=200;
    vector<int>result(32);
    for(int i=0;i<32;i++){
        result[i]=lower_bound + rand()%(p-lower_bound); //stores the random number in result 
    }
    return result;
}
vector<int> Deffie_Helman::Calculate_PublicKey(vector<int>private_key)
{
    vector<int>result(32);
    for(int i=0;i<32;i++)
    {
        result[i]=Modular_Exponential(p,g,private_key[i]);
    }
    return result;
}
string Deffie_Helman::shared_key(vector<int>private_key,vector<int>public_key){
    //calculate PU^PR mod p
    string result;
    for(int i=0;i<32;i++)
    {
        int k=Modular_Exponential(p,public_key[i],private_key[i]);
        result=result+dectohex[k%16];
    }
    return result;
}
#endif