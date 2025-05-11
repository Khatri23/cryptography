#ifndef ELLIPTICAL_CURVE
#include<iostream>
#include<openssl/bn.h>
#include<openssl/rand.h>
#include<unordered_map>
#include"AES.h"
//elliptical curve defined on secp256k k means Koblitz curve E(0,7) prime is 256 bits long .. y^3=x^2+7.
using std::string;
std::unordered_map<char,string>hextobin={
    {'0',"0000"},
    {'1',"0001"},
    {'2',"0010"},
    {'3',"0011"},
    {'4',"0100"},
    {'5',"0101"},
    {'6',"0110"},
    {'7',"0111"},
    {'8',"1000"},
    {'9',"1001"},
    {'A',"1010"},
    {'B',"1011"},
    {'C',"1100"},
    {'D',"1101"},
    {'E',"1110"},
    {'F',"1111"}
};


class Elliptical_curve{
private:
    BIGNUM *prime;
    BIGNUM * n;//multiplicative order
    BIGNUM *a,*b;//coefficient.
    BIGNUM **G;
    BN_CTX *ctx;//for cleanup
public:
    Elliptical_curve();
    ~Elliptical_curve(){
        BN_free(prime);
        BN_free(n);
        BN_free(a),BN_free(b);
        BN_free(G[0]),BN_free(G[1]);
        BN_CTX_free(ctx);
        delete []G;
    }
    char * Private_Key()
    {
        BIGNUM *rnd=BN_new();
        //private key should be less than that n 
        BN_rand(rnd,BN_num_bits(n)-1,0,0);
        char * str=BN_bn2hex(rnd);
        BN_free(rnd);
        return str;
    }

    std::pair<char*,char*> Public_key(const char * PR)
    {
        //PUBLIC_KEY= PR*G(x,y). we will use point doubling technique. algorithm called doubling and addition.
        string bin;
        int i=0;
        while(PR[i]!='\0'){
            bin=bin+hextobin[PR[i++]];
        }
       auto key= CALCULATE(bin,G);
        char *x=BN_bn2hex(key.first);
        char *y=BN_bn2hex(key.second);
        BN_free(key.first),BN_free(key.second);
        return {x,y};
    }

    std::pair<char*,char*> Deffie_Helman(char* ,std::pair<char*,char*>&);

    std::pair<std::pair<char*,char*>,string>EncryptAES(std::pair<char*,char*>&,string); //gives hint , cipher

    string DecryptAES(char*,std::pair<char*,char*>,string&);

    private:
    std::pair<BIGNUM*,BIGNUM*> CALCULATE(string& ,BIGNUM **);
    std::pair<BIGNUM*,BIGNUM*>Double(BIGNUM*,BIGNUM *);
    std::pair<BIGNUM *,BIGNUM*>Formula(BIGNUM*,BIGNUM*,BIGNUM**,BIGNUM*);
    std::pair<BIGNUM *, BIGNUM*>Addition(BIGNUM*,BIGNUM*,BIGNUM**);
};

Elliptical_curve::Elliptical_curve():prime(nullptr),n(nullptr){ //setup for processing public information.
    ctx=BN_CTX_new();
    a=BN_new();b=BN_new();
    BN_set_word(a,3),BN_set_word(b,7);
    BN_hex2bn(&prime,"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    BN_hex2bn(&n,"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    G= new BIGNUM*[2];
    G[0]=G[1]=nullptr;
    //base point.
    BN_hex2bn(&G[0],"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"); //x-coordinate
    BN_hex2bn(&G[1],"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");//y-coordinate

}

std::pair<BIGNUM*,BIGNUM*> Elliptical_curve::CALCULATE(string& bin,BIGNUM** co)
{
    int i=0; //using double and add algorithm
    while(bin[i]=='0')i++; //skip MSB's 0's and a 1.
    i++;
    std::pair<BIGNUM*,BIGNUM*>temp={co[0],co[1]};
    while(i < bin.length())
    {
        temp=Double(temp.first,temp.second);
        if(bin[i]=='1'){
            temp=Addition(temp.first,temp.second,co);
        }
        i++;
    }
    return temp;
}

std::pair<BIGNUM*,BIGNUM*>Elliptical_curve::Formula(BIGNUM*x1,BIGNUM* x2,BIGNUM**slope,BIGNUM*y1){
/*
        x.new=s^2-x1-x2 % p
        y.new=s(x1-x.new)-y1 %p
    */
   BIGNUM *s=BN_new();
   if(BN_mul(s,*slope,*slope,ctx)==0){
    std::cerr<<"Failed";
    exit(1);
   }
   BIGNUM * add=BN_new();
   if(BN_add(add,x1,x2)==0){
    std::cerr<<"failed";
    exit(1);
   }
   BIGNUM * newx=BN_new();
   if(BN_mod_sub(newx,s,add,prime,ctx)==0){
    std::cerr<<"Failed";
    exit(1);
   }
   BN_free(s);
   s=BN_new();
   if(BN_mod_sub(s,x1,newx,prime,ctx)==0){
    std::cerr<<"Failed";
    exit(1);
   }
   BIGNUM *t=BN_new();
   if(BN_mul(t,*slope,s,ctx)==0){
    std::cerr<<"failed";
    exit(1);
   }
   BIGNUM*newy=BN_new();
   if(BN_mod_sub(newy,t,y1,prime,ctx)==0){
    std::cerr<<"failed";
    exit(1);
   }
   BN_free(s);
   BN_free(add);
   BN_free(t);
   return{newx,newy};
}

std::pair<BIGNUM*,BIGNUM*>Elliptical_curve::Double(BIGNUM*x,BIGNUM*y){
    //slope of tangent. %prime.
    BIGNUM *num=BN_new();//3x^2+a/2*y mod p
    if(BN_mul(num,x,x,ctx)==0){
        std::cerr<<"Failed";
        exit(1);
    }
    if(BN_mul(num,a,num,ctx)==0){
        std::cerr<<"Failed";
        exit(1);
    }
    BIGNUM * den=BN_new();
    BN_set_word(den,2);
    if(BN_mul(den,den,y,ctx)==0){
        std::cerr<<"Failed";
        exit(1);
    }
    BIGNUM * inv=BN_new();
    if(BN_mod_inverse(inv,den,prime,ctx)==0){
        std::cerr<<"falied";
        exit(1);
    }
    BIGNUM * slope=BN_new();
    if(BN_mod_mul(slope,num,inv,prime,ctx)==0){
        std::cerr<<"failed";
        exit(1);
    }
    
    BN_free(num);
    BN_free(den);
    BN_free(inv);
    return Formula(x,x,&slope,y);
}

std::pair<BIGNUM*,BIGNUM*>Elliptical_curve::Addition(BIGNUM* x1,BIGNUM*y1,BIGNUM**co)
{
    //slope=y2-y1/x2-x1 mod p
    BIGNUM *Y=BN_new();
    if(BN_mod_sub(Y,co[1],y1,prime,ctx)==0){
        std::cerr<<"failed";
        exit(1);
    }
    BIGNUM *X=BN_new();
    if(BN_mod_sub(X,co[0],x1,prime,ctx)==0){
        std::cerr<<"failed";
        exit(1);
    }
    BIGNUM * inv=BN_new();
    if(BN_mod_inverse(inv,X,prime,ctx)==0){
        std::cerr<<"failed";
        exit(1);
    }
    BIGNUM* slope=BN_new();
    if(BN_mod_mul(slope,Y,inv,prime,ctx)==0){
        std::cerr<<"failed";
        exit(1);
    }
    BN_free(Y);
    BN_free(inv);
    BN_free(X);
    return Formula(x1,co[0],&slope,y1);
}

std::pair<char*,char*>Elliptical_curve:: Deffie_Helman(char* Privatekey,std::pair<char*,char*>&Publickey){
    BIGNUM * PK=BN_new();
    BN_hex2bn(&PK,Privatekey);
    BIGNUM ** PU=new BIGNUM*[2];
    PU[0]=PU[1]=nullptr;
    BN_hex2bn(&PU[0],Publickey.first),BN_hex2bn(&PU[1],Publickey.second);
    string bin;
    int i=0;
    while(Privatekey[i]!='\0') bin=bin+hextobin[Privatekey[i++]];
    auto key=CALCULATE(bin,PU);
    char *x=BN_bn2hex(key.first);
    char *y=BN_bn2hex(key.second);
    BN_free(key.first),BN_free(key.second);
    BN_free(PK);
    BN_free(PU[0]);
    BN_free(PU[1]);
    delete []PU;
    return {x,y};
}

std::pair<std::pair<char*,char*>,string>Elliptical_curve::EncryptAES(std::pair<char*,char*>&Publickey,string message)
{
    BIGNUM ** PU=new BIGNUM*[2];
    PU[0]=PU[1]=nullptr;
    BN_hex2bn(&PU[0],Publickey.first),BN_hex2bn(&PU[1],Publickey.second);
    BIGNUM * k=BN_new(); //secret point KPU. x.coordiate value and send KG.
    BN_rand(k,128,0,0);
    char * Sk=BN_bn2hex(k);
    BN_free(k);
    string bin;
    int i=0;
    while(Sk[i]!='\0') bin=bin+hextobin[Sk[i++]];
    string key(BN_bn2hex(CALCULATE(bin,PU).first)); //using x coordinate to encrypt the message.
    Encryption obj(message,key); //it will take the 128 bits LSB.
    auto hint=CALCULATE(bin,G); //KG
    char * x=BN_bn2hex(hint.first);
    char * y=BN_bn2hex(hint.second);
    BN_free(hint.first),BN_free(hint.second);
    BN_free(PU[0]);
    BN_free(PU[1]);
    delete []PU;
    return {{x,y},obj.encrypt_message()};
}

string Elliptical_curve::DecryptAES(char * privatekey,std::pair<char*,char*>hint,string&cipher)
{
    //PRhint
    BIGNUM ** PU=new BIGNUM*[2];
    PU[0]=PU[1]=nullptr;
    BN_hex2bn(&PU[0],hint.first),BN_hex2bn(&PU[1],hint.second);
    string bin;
    int i=0;
    while(privatekey[i]!='\0'){
        bin=bin+hextobin[privatekey[i++]];
    }
    string key(BN_bn2hex(CALCULATE(bin,PU).first));
    Decryption obj(cipher,key);
    BN_free(PU[0]);
    BN_free(PU[1]);
    delete []PU;
    return obj.decrypt_message();
}

#endif