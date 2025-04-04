#ifndef AES
#define AES
#include<iostream>
#include<vector>
#include<sstream>
#include<iomanip>
#include<sstream>
#include<cstdint>
#include<ctime>
using std::string,std::vector;
int row(int val){return (val >> 4);} //shifting to the right since MSB is filled with 0
int column(int val){
    return ((val) &0x0f);
} //for extracting last 4 bit value anding with 00001111 is like discarding MSB 4 bit
    //subbyte look up table
    std::vector<std::vector<int>> sbox = {
        {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
        {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
        {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
        {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
        {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
        {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
        {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
        {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
        {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
        {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
        {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
        {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
        {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
        {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
        {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
        {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
    };
//for testing let key
const vector<vector<int>>key={
    {0x0f,0x47,0x0c,0xaf},
    {0x15,0xd9,0xb7,0x7f},
    {0x71,0xe8,0xad,0x67},
    {0xc9,0x59,0xd6,0x98}
};

class Key_transformation
{
private:
    vector<vector<int>>state;
    vector<int>Rconstant={0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};
    int rc;
public:
    vector<vector<int>>words;//44 words assuming 128 environment.
    Key_transformation();
private:
    vector<int>RoundConstant(vector<int>);
    vector<int>XOR(vector<int>A,vector<int>B)
    {
        vector<int> result(4);
        for(int i=0;i<4;i++){
            result[i]=A[i] xor B[i];
        }
        return result;
    }
};

Key_transformation::Key_transformation():rc(0)
{
    words.resize(44);
    state=key;
    for(int i=0;i<4;i++){ //initial words w0 .. w3
        vector<int>temp;
        for(int j=0;j<4;j++){
            temp.push_back(state[j][i]);
        }
        words[i]=temp;
    }
    //precalculate the words for each round
    for(int i=4;i<44;i++)
    {
        vector<int>temp=words[i-1];
        if(i%4==0){
            temp=RoundConstant(temp);
        }
        words[i]=XOR(temp,words[i-4]);
    }
}

vector<int> Key_transformation::RoundConstant(vector<int>value)
{
    vector<int>result(4);
    for (int i = 0; i < 4; i++) {
        result[i] = value[(i + 1) % 4];
    }
    for (int i = 0; i < 4; i++) {
        result[i] = sbox[row(result[i])][column(result[i])];
    }
    //only the first byte is xored 
    result[0]=result[0] xor Rconstant[rc++];
    return result;
}

class Encryption
{
protected:
    vector<vector<int>>state;
    vector<vector<int>>mul={
        {0x02,0x03,0x01,0x01},
        {0x01,0x02,0x03,0x01},
        {0x01,0x01,0x02,0x03},
        {0x03,0x01,0x01,0x02}
    };
    Key_transformation* key;
    int w;//proportional to the round
public:
    std::string Hash_key;
    Encryption(){}
    Encryption(vector<int>&,bool); 
    Encryption(std::string );
    string encrypt_message(string plaintext)
    {
        vector<vector<int>>P(4,vector<int>(4,0));
        int idx=0;
        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                P[j][i]=int(plaintext[idx++]);
            }
        }
        std::stringstream ss;
        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                ss << std::hex << std::setw(2) << std::setfill('0') << (state[j][i] xor P[j][i]);
            }
        }
        return ss.str().substr(0,plaintext.length()*2);
    }
    string Decrypt_Message(string plaintext){
        vector<vector<int>>P(4,vector<int>(4,0));
        int idx=0;
        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                if(idx >= plaintext.length()) break;
                std::string temp;
                temp.push_back(plaintext[idx]);
                temp.push_back(plaintext[idx+1]);
                P[j][i]=std::stoi(temp,nullptr,16);
                idx+=2;
            }
        }
        std::string ss;
        for(int i=0;i<4;i++){
            for(int j=0;j<4;j++){
                ss.push_back(char(state[j][i] xor P[j][i]));
            }
        }
        return ss.substr(0,plaintext.length()/2);
    }
    static int multiply(int,int);

protected:
    void SubByte();
    void shiftRows();
    void AddRoundKey();
    vector<vector<int>>MixColumn(vector<vector<int>>&,vector<vector<int>>&);
};

Encryption ::Encryption(std::string Pkey):w(0){ //this is only needed for hash key.
    state.resize(4,std::vector<int>(4,0));
    key=new Key_transformation();
    AddRoundKey();
    for(int i=1;i<=9;i++){
        SubByte();
        shiftRows();
        state=MixColumn(mul,state);
        AddRoundKey();
        
    }
    SubByte();
    shiftRows();
    AddRoundKey();
    std::stringstream ss;
    for(int i=0;i<4;i++){
        for(int j=0;j<4;j++){
            ss << std::hex << std::setw(2) << std::setfill('0') << (state[j][i] );
        }
    }
    Hash_key=ss.str();
}

Encryption::Encryption(vector<int>&nonce,bool carry):w(0) //CTR mode 
{
    key=new Key_transformation();
    state.resize(4,std::vector<int>(4,0));//padding with 00
        //build the state matrix.
    int index=nonce.size()-1;
    index--;
    //carry 1 will act as my incrementer zero means no incrementer and j0 is used for the encrypting the GHASH.
    while(carry && index >=12){
        nonce[index]=nonce[index]+carry;
        carry=nonce[index] >>8;
        nonce[index]=nonce[index] & 0xff;
        index--;
    }
    index=0;
    for(int i=0;i<4;i++)
    {
        for(int j=0;j<4;j++)
        {
           state[j][i]=nonce[index++];
        }
    }
    AddRoundKey();
    for(int i=1;i<=9;i++){
        SubByte();
        shiftRows();
        state=MixColumn(mul,state);
        AddRoundKey();
        
    }
    SubByte();
    shiftRows();
    AddRoundKey();
}

void Encryption::SubByte()
{
    for(int i=0;i<4;i++){
        for(int j=0;j<4;j++){
            state[i][j]=sbox[row(state[i][j])][column(state[i][j])] ;//new state after substitution
        }
    }
}

void Encryption::shiftRows(){
    for(int i=1;i<4;i++){
        vector<int>temp(4);
        int idx=0;
        for(int j=0;j<4;j++){
            temp[j]=state[i][(j+i)%4];
        }
        state[i]=temp;
    }
}

void Encryption::AddRoundKey()
{
    //xoring the words and the state matrix.
    for(int i=0;i<4;i++)
    {
        for(int j=0;j<4;j++)
        {
            state[j][i]=state[j][i] xor key->words[w][j];
        }
        w++;
    }
}
int Encryption:: multiply(int a,int b)
{
    int shift=a;//used for intermediate results
    int result=0;
   for(int i=0;i<8;i++)
   {
    if(b & (1<<i)) result=result ^shift; //xoring the position of the bits in b.
    shift=shift << 1;
    if(shift & 0x100) shift=(shift ^ 0x1B)&0xff; //mask of degree n 100 its just to check if x8 is set or not 0x1B is the irreducable polynomial
   }//0xff for the 8 bit masking
    //since we are dealing in GF(2^8)
    return result;
}

vector<vector<int>>Encryption:: MixColumn(vector<vector<int>>& a,vector<vector<int>>& b)
{
   vector<vector<int>>result(4,vector<int>(4));
    for(int i=0;i<4;i++)
    {
        for(int j=0;j<4;j++)
        {
            int sum=0;
            for(int k=0;k<4;k++)
            {
                sum=sum ^ multiply(a[i][k],b[k][j]);
            }
            result[i][j]=sum;
        }
    }
   return result;
}

#endif