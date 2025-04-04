#ifndef GCM
#include "CTRAES.h"
#include<bitset>
#include<unordered_map>
#include<cmath>
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
    {'a',"1010"},
    {'b',"1011"},
    {'c',"1100"},
    {'d',"1101"},
    {'e',"1110"},
    {'f',"1111"}
};
class GCM:public Encryption{
    //GHASH and ctr.
private:
    std::string BKEY;//binary value for the key. (we will be using multiplication in GF(2^128)).
    std::bitset<128> MAC;
public:
    GCM():Encryption(){}
    GCM(std::vector<int>&nonce,bool c):Encryption(nonce,c){}
    GCM(std::string key):Encryption(key){
        std::string k;
        for(int i=0;i<Hash_key.size();i++){
            BKEY=BKEY+hextobin[Hash_key[i]];
        }
        
    }
    void GHASH(string);
    std::string MACS(){
        uint64_t high = (MAC >> 64).to_ullong();  // Extract upper 64 bits    
        std::stringstream ss;
        ss << std::hex << std::setw(16) << std::setfill('0') << high;//only 64 bit mac
        return ss.str();
    }
private:
    std::bitset<128> multiply(std::bitset<128>shifts){ //multiply in GF(2^128).
        std::bitset<128>result;
        std::bitset<128>mask("10000111"); //irreducable polynomial x^128+x^7+x^2+x+1.
        for(int i=0;i < 128;i++){
            if(BKEY[i]=='1'){
                result =result ^ shifts;
            }
            bool msb=shifts[127];
            shifts = shifts << 1;
            if(msb==1) shifts=shifts ^ mask;
        }
        return result;
    }
};

void GCM::GHASH(string cipher){
    int len=cipher.length()*4;//in binary.
    int padding= 128*(ceil(double(len)/128.0))-len;
    //now we multiply the blocks with of 128 with the hashkey. and chain with the xor for 128 bit MAC.
    std::string bin;
    for(int i=0;i<cipher.size();i++){
        bin+=hextobin[cipher[i]];
    }
    while(padding--) bin.push_back('0');
    MAC= MAC ^    multiply(std::bitset<128>(bin));
}


#endif