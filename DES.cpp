#include "DES.h"
#include<unordered_map>
#include<iomanip>
#include<sstream>
// mapping of binary to hex
std::unordered_map<string,string>bintohex={
    {"0000","0"},
    {"0001","1"},
    {"0010","2"},
    {"0011","3"},
    {"0100","4"},
    {"0101","5"},
    {"0110","6"},
    {"0111","7"},
    {"1000","8"},
    {"1001","9"},
    {"1010","A"},
    {"1011","B"},
    {"1100","C"},
    {"1101","D"},
    {"1110","E"},
    {"1111","F"}
};

//mapping of hex to binary
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

//mapping for S-box
std::unordered_map<string,int>bintodec={
    {"0000",0},
    {"0001",1},
    {"0010",2},
    {"0011",3},
    {"0100",4},
    {"0101",5},
    {"0110",6},
    {"0111",7},
    {"1000",8},
    {"1001",9},
    {"1010",10},
    {"1011",11},
    {"1100",12},
    {"1101",13},
    {"1110",14},
    {"1111",15}
};

//mapping of decimal to binary
std::unordered_map<int,string>dectobin={
    {0,"0000"},
    {1,"0001"},
    {2,"0010"},
    {3,"0011"},
    {4,"0100"},
    {5,"0101"},
    {6,"0110"},
    {7,"0111"},
    {8,"1000"},
    {9,"1001"},
    {10,"1010"},
    {11,"1011"},
    {12,"1100"},
    {13,"1101"},
    {14,"1110"},
    {15,"1111"}
};

vector<int>IP_BOX={
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
     };

vector<int>Expansion_BOX{
    32, 1, 2, 3, 4, 5, 4, 5,
    6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27,
    28, 29, 28, 29, 30, 31, 32, 1
};

 vector<int> P_BOX{
    16,  7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};

vector<int>F_BOX{
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};


string tobinary(string plaintext, bool truncate)
{
    string result;
     string temp;
    for(auto x:plaintext)
    {
        int a=int(x);
        std::stringstream ss;
        ss<<std::hex<<a;
        ss>> temp;
        for(auto s:temp)
        {
            result=result+hextobin[toupper(s)];
        }
        if(truncate) result.pop_back();
    }
    return result;
}
string Permute(string value,vector<int>matrix,int n)
{
    string result;
    for(int i=0;i<n;i++)
    {
        result.push_back(value[matrix[i]-1]);
    }
    return result;
}
int index(char a,char b,char c,char d)
{
    string val;
    val.push_back(a);
    val.push_back(b);
    val.push_back(c),
    val.push_back(d);
    return bintodec[val];
}

//plain text to Binary value conversion
 Encryption::Encryption(string plaintext,string key)
 {
    this->plaintext=tobinary(plaintext,false);
    int n=this->plaintext.size();
    if(n < 64){
        //append the 0's;
        for(int i=1;i<=64-n;i++) this->plaintext.push_back('0');
    }
    key_Str obj(key);
    roundKey=obj.Get_roundkey();
    std::cout<<"plain text= "<<plaintext<<std::endl;

 }

string Encryption::encrypt(){
    string initial=Permute(plaintext,IP_BOX,64);
    //splitting into LPT and RPT 32 bit.
    string left(initial.begin(),initial.begin()+32);
    string right(initial.begin()+32,initial.end());

    for(int rounds=0;rounds < 16;rounds++)
    {
        string expansion=Permute(right,Expansion_BOX,48);
        expansion=XOR(expansion,roundKey[rounds],48);
        string str="";
        for(int i=0;i<S_box.size();i++)
        {
            int row=index('0','0',expansion[i*6],expansion[i*6+5]); //extracting the first and last bit of the 6 bits
            int column=index(expansion[i*6+1],expansion[i*6+2],expansion[i*6+3],expansion[i*6+4]);//extracting the mid part
            int val=S_box[i][row][column];
            str=str+dectobin[val];
        }
        str=Permute(str,P_BOX,32);
        right=XOR(str,left,32);
        left=str;
        
    }
    string result=right+left;
    result=Permute(result,F_BOX,F_BOX.size());
    //decode the value to ascii
    std::cout<<result<<std::endl;
    string cipher;
    for(int i=0;i<8;i++)
    {
        left=right="";
        left.push_back(result[i * 8]);
        left.push_back(result[i * 8 + 1]);
        left.push_back(result[i * 8 + 2]);
        left.push_back(result[i * 8 + 3]);

        // Last 4 bits go to right
        right.push_back(result[i * 8 + 4]);
        right.push_back(result[i * 8 + 5]);
        right.push_back(result[i * 8 + 6]);
        right.push_back(result[i * 8 + 7]);

        string hexcode=bintohex[left]+bintohex[right];
        cipher=cipher+hexcode;
    }
    return cipher;
}


string Encryption::XOR(string a,string b,int n)
{
    string result;
    for(int i=0;i<n;i++)
    {
        if(a[i]==b[i])result.push_back('0');
        else result.push_back('1');
    }
    return result;
}



//working for keys
key_Str::key_Str(string key)
{
    this->key=key;
    BinKey=tobinary(key,true);
    compute();
}
void key_Str::compute()
{
    vector<int>shift_table={
        1, 1, 2, 2,
        2, 2, 2, 2,
        1, 2, 2, 2,
        2, 2, 2, 1
    };    
    //dividing into 28 L and 28 R
    string left(BinKey.begin(),BinKey.begin()+28);
    string right(BinKey.begin()+28,BinKey.end());
    //for 16 round key generating 
    for(int i=0;i<16;i++)
    {
        left=SShift(left,shift_table[i]);
        right=SShift(right,shift_table[i]);
        string combination=left+right;
        combination=Permute(combination,key_comp,48);
        round_key.push_back(combination);
    }

}
string key_Str::SShift(string  val,int n)
{
    
    while(n--)
    {
        string s;
        for(int i=1;i<val.length();i++)
        {
            s.push_back(val[i]);
        }
        s.push_back(val[0]);
        val=s;
    }
    return val;
}


int main()
{
    Encryption obj("Anjuli","security");
    std::cout<<obj.encrypt();
    return 0;
}

