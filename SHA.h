#ifndef SHA
#include<iostream>
#include<vector>
#include<cstdint>
#include<cmath>
#include<sstream>
#include<iomanip>
using std::vector;
#define SHA
//core logic for SHA-512.
class SHA_512
{
private:
    uint64_t A = 0x6a09e667f3bcc908; //fraction part of first 8 primes square root.
    uint64_t B = 0xbb67ae8584caa73b;
    uint64_t C = 0x3c6ef372fe94f82b;
    uint64_t D = 0xa54ff53a5f1d36f1;
    uint64_t E = 0x510e527fade682d1;
    uint64_t F = 0x9b05688c2b3e6c1f;
    uint64_t G = 0x1f83d9abfb41bd6b;
    uint64_t H = 0x5be0cd19137e2179;
    int idx;
public:
    vector<uint64_t> W; //per each block message
public:
    const static vector<uint64_t> Constant; //first 80 fraction part of prime cube root;
    SHA_512(vector<unsigned char>&message);
    std::string Hash();
private:
    //operations 
    uint64_t Ch(uint64_t e, uint64_t f,uint64_t g)
    {
        return (e & f) ^ (~e & g);
    }
    uint64_t Maj(uint64_t a,uint64_t b, uint64_t c){
        return (a & b) ^ (b & c) ^ (a & c); 
    }
    uint64_t Right_Rotate(uint64_t a,int n)
    {
        return (a >> n)| (a << (64-n));
    }
    uint64_t Shift_Right(uint64_t a, int n){
        return a >>n;
    }
    uint64_t SigmE(uint64_t e){
        return Right_Rotate(e,14) ^ Right_Rotate(e,18) ^ Right_Rotate(e,41);
    }
    uint64_t SigmA(uint64_t a){
        return Right_Rotate(a,28) ^ Right_Rotate(a,34) ^ Right_Rotate(a,39);
    }
    void message_schedule();
    void Compression_function();
    void Prepare_Block(vector<unsigned char>&);
};
const vector<uint64_t> SHA_512::Constant  = { 
    0x428a2f98d728ae22, 0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
    0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210,
    0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910,
    0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60,
    0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9,
    0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817 };


SHA_512::SHA_512(vector<unsigned char>&message):idx(0)
{
    long long sz=message.size();
    const int bs=112; //block size is 896 bits > than is move to next block.
    int block=sz/bs +1;  
    Prepare_Block(message);
    std::cout<<block<<" needed block!\n";
    block--;
    while(block > 0)
    {
        message_schedule();
        Compression_function();
        W.clear();
        Prepare_Block(message);
        block--;
    }
    W[15]=sz*8; //total bits for that length can support upto 2^128. (2^64)
    message_schedule();
    Compression_function();
}
void SHA_512::Prepare_Block(vector<unsigned char>& text)
{
    W.resize(80,0x0000000000000000);
    int i=0;
    while(idx < text.size() && i < 14)
    {
        std::stringstream ss;
        int d=idx+8;
        for(;idx < d && idx < text.size();idx++)
        {
            if(i==13 && ss.str().length()==14) {
                idx++;
                break;
            }
            ss<<std::setw(2)<<std::setfill('0')<<std::hex<<int(text[idx]);
        }
        if(ss.str().length() < 16){
            ss<<0x80; //pad with 1
            while(ss.str().length() < 16) ss<<0x00;
        }
        W[i]=ss.hex;
        i++;
    }

}   
void SHA_512::message_schedule()
{
    for(int i=16;i<80;i++)
    {
        uint64_t wordA=Right_Rotate(W[i-2],1) xor Right_Rotate(W[i-2],61) xor Shift_Right(W[i-2],6);
        uint64_t wordB=Right_Rotate(W[i-15],1) xor Right_Rotate(W[i-15],8) xor Shift_Right(W[i-15],7);
        W[i]=wordA +W[i-7] + wordB + W[i-16];
    }
}
void SHA_512::Compression_function()
{
    uint64_t AA=A, BB=B,CC=C,DD=D,EE=E,FF=F,GG=G,HH=H; //holds the intermediate hash result from each round.
    for(int t=0;t < 80;t++) //process begins.
    {
        uint64_t T1=HH + Ch(EE,FF,GG) + SigmE(EE) + W[t] +Constant[t];
        uint64_t T2=SigmA(AA)+Maj(AA,BB,CC);
        HH=GG; GG=FF; FF=EE; EE=DD + T1;
        DD=CC; CC=BB; BB=AA; AA=T1+T2;
    }
    A+=AA; 
    B+=BB;
    C+=CC;
    D+=DD;
    E+=EE;
    F+=FF;
    G+=GG; H+=HH; //chain variable is obtained final result is the resulting hash.
}
std::string ToHex(uint64_t a) //helper function
{
    std::stringstream ss;
    ss << std::hex<<a;
    std::string temp;
    for(int i=ss.str().length();i < 16;i++)
    {
        temp.push_back('0');
    }
    temp=temp+ss.str();
    return temp;
}
std::string SHA_512::Hash() 
{
    std::string result;
    result=ToHex(A)+ToHex(B)+ToHex(C)+ToHex(D)+ToHex(E)+ToHex(F)+ToHex(G)+ToHex(H);
    return result; //512 output
}
#endif