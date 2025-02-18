#include<iostream>
#include"Deffie.h"
#include"AES.h"
#include<fstream>
class Inventory{
private:
    vector<int>private_key; //other's can't have access to this key
public:
    vector<int>public_key;
    Inventory(){
        private_key.reserve(32);
        public_key.reserve(32);
    }
    void set_private(vector<int>private_key){
        this->private_key=private_key;
    }
    vector<int>get_privateKey(){
        if(private_key.empty()){
            std::cerr<<"No private key set!";
            exit(1);
        }
        return private_key;
    }
    void saveToFile(const std::string& filename) {
        std::ofstream outFile(filename, std::ios::binary);
        if (!outFile) {
            std::cerr << "Error opening file for writing!" << std::endl;
            return;
        }
        size_t private_size = private_key.size();
        size_t public_size = public_key.size();

        // Write sizes first
        outFile.write(reinterpret_cast<char*>(&private_size), sizeof(private_size));
        outFile.write(reinterpret_cast<char*>(&public_size), sizeof(public_size));

        // Write private and public keys
        outFile.write(reinterpret_cast<char*>(private_key.data()), private_size * sizeof(int));
        outFile.write(reinterpret_cast<char*>(public_key.data()), public_size * sizeof(int));

        outFile.close();
    }
    // Load Inventory from file
    void loadFromFile(const std::string& filename) {
        std::ifstream inFile(filename, std::ios::binary);
        if (!inFile) {
            std::cerr << "File not found!" << std::endl;
            return;
        }
        size_t private_size, public_size;
        // Read sizes first
        inFile.read(reinterpret_cast<char*>(&private_size), sizeof(private_size));
        inFile.read(reinterpret_cast<char*>(&public_size), sizeof(public_size));

        // Resize vectors and read data
        private_key.resize(private_size);
        public_key.resize(public_size);

        inFile.read(reinterpret_cast<char*>(private_key.data()), private_size * sizeof(int));
        inFile.read(reinterpret_cast<char*>(public_key.data()), public_size * sizeof(int));

        inFile.close();
    }

};
void Initiate(string &key)
{
    std::ifstream ifile;
    std::ofstream efile("encrypt.txt");
    ifile.open("text.txt");
    int i=0;
    char c;
    string text;
    while (ifile.get(c))
    {
        text.push_back(c);
        if(text.size()==16){
            Encryption obj(text,key);
            efile<< obj.encrypt_message()<<std::endl;
            text.clear();
        }
    }
    if(!text.empty()){ //remaining 
        Encryption obj(text,key);
        efile << obj.encrypt_message();
        text.clear();
    }
    efile.close();
    ifile.close();
    ifile.open("encrypt.txt");
    while(std::getline(ifile,text))
    {
        Decryption obj(text,key);
        std::cout<<obj.decrypt_message();
    }
    ifile.close();
}

void simulate(Inventory& user)
{
    Deffie_Helman key;
    std::string shared_key;
    Inventory other;
    std::cout<<"Which user 1 or 3:";
    int u;
    std::cin>>u;
    switch(u)
    {
        case 1:
            other.loadFromFile("user1.txt");
            shared_key=key.shared_key(user.get_privateKey(),other.public_key);
            std::cout<<"Shared key: " <<shared_key<<std::endl;
            Initiate(shared_key);
            break;
        case 3:
            other.loadFromFile("user3.txt");
            shared_key=key.shared_key(user.get_privateKey(),other.public_key);
            std::cout<<"Shared key: " <<shared_key<<std::endl;
            Initiate(shared_key);
            break;
        default: std::cout<<"No user\n";
    }
}
int main()
{
    string computer="user2.txt";
    std::cout<<"-----------------------------------------"<<computer<<"---------------------------------------"<<std::endl;

    Deffie_Helman key;
    std::ifstream ifile(computer);
    if(ifile){ //long term private key so that i don't generate every time
        ifile.close();
        Inventory obj;
        obj.loadFromFile(computer);
        simulate(obj);
    }
    else{
        Inventory obj;
        obj.set_private(key.Generate_PrivateKey());
        obj.public_key=key.Calculate_PublicKey(obj.get_privateKey());
        obj.saveToFile(computer);
    }
    return 0;
}