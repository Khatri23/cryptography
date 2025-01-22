//playfair cipher
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
char * Word(const char * plaintext,char & filler)
{
    int n=strlen(plaintext);
    char * newtext=(char *)malloc(sizeof(char)*2*n+1); // at worst all element same then it takes size double
    bool arr[26]; //storing the filler candidates
    memset(arr,false,sizeof(arr));
    for(int i=0;i<26;i++){
        arr[plaintext[i]-'a']=true ; //seen 
    }
    //searching in arr from last as last elements have least frequency
    for(int i=25;i>=0;i--){
        if(arr[i]==false) {
            filler=char('a'+i); //ascii offset from a 
            break;
        }
    }
    int j=1,i=1;
    newtext[0]=plaintext[0];
    //adding filler between repeating groups
    for(i=1;i<n;i++)
    {
        if(newtext[j-1]==plaintext[i])
        {
            newtext[j++]=filler;
        }
        newtext[j++]=plaintext[i];
    }
    //checking wheather the length is odd or even if even add filler to end
    if(j %2!=0) newtext[j++]=filler;
    newtext[j]='\0';
    return newtext;
}
int encode(int i,int j)
{
    return (i*10+j);
}
bool check(int i,int j,char c)
{
    if(c=='r') {
        return i/10==j/10;
    }
    else if(c=='c'){
        return i%10==j%10;
    }
    return false;
}
char * Encrypt(const char *,const char *,char &);
char * Decrypt(const char *,char *,char&);
int main()
{
    //assuming the system receives the lowercase alphabets.
    const char* key="security";
    const char * plaintext="information";
    char filler;
    char * cipher=Encrypt(key,plaintext,filler);
    printf("ciphertext= %s",cipher);
    char *text=Decrypt(key,cipher,filler);
    printf("\ndecrypt= %s",text);
    free(cipher);
    free(text);
    return 0;
}

char * Encrypt(const char * key,const char * plaintext,char & filler)
{
    char * newtext=Word(plaintext,filler);
    char matrix[5][5];
    int seen[26]; //storing the index of the alphabet for faster lookups and encoding int the form row*10+column
    // decode=row=seen/10 and column=seen%10.
    memset(seen,-1,sizeof(seen));
    int k=0;
    int n=strlen(key);
    int a=0;
    //8,9 ie. i,j are the pairs
    for(int i=0;i<5;i++)
    {
        for(int j=0;j<5;j++)
        {
            //firslty key element is filled in the matrix
            if(k < n){
                while(seen[key[k]-'a']!=-1) k++;

                if(k < n){
                    if(key[k]=='i' || key[k]=='j') {
                        seen[8]=seen[9]=encode(i,j);
                    }
                    seen[key[k]-'a']=encode(i,j);
                    matrix[i][j]=key[k++];
                }
            }
            else{ // rest remaining character.
                while(seen[a]!=-1) a++;
                if(a==8 || a==9) seen[8]=seen[9]=encode(i,j); //i,j are the pairs so same location
                seen[a]=encode(i,j);
                matrix[i][j]=char('a'+a);
            }
        }
    }

    for(int i=0;i<5;i++){
        for(int j=0;j<5;j++) printf("%c ",matrix[i][j]);
        printf("\n");
    }
    printf("plaintext= %s\n",newtext);
   n=strlen(newtext);
   char * cipher=(char*)malloc(sizeof(char)*n); //new memory allocation for cipher sizeof plaintext
   for(int i=0;i<n;i+=2)
   {
        if(check(seen[newtext[i]-'a'],seen[newtext[i+1]-'a'],'r')){ //same row shift column to right
            cipher[i]=(matrix[seen[newtext[i]-'a']/10][(seen[newtext[i]-'a']%10+1)%5]); //extraction of row and column and shifiting the column
            cipher[i+1]=(matrix[seen[newtext[i+1]-'a']/10][(seen[newtext[i+1]-'a']%10+1)%5]);
        }
        else if(check(seen[newtext[i]-'a'],seen[newtext[i+1]-'a'],'c')){ // same column shift row to the down
            cipher[i]=matrix[(seen[newtext[i]-'a']/10+1)%5][seen[newtext[i]-'a']%10];
            cipher[i+1]=matrix[(seen[newtext[i+1]-'a']/10+1)%5][seen[newtext[i+1]-'a']%10];
        }
        else{ // rectangle swap
            cipher[i]=matrix[seen[newtext[i]-'a']/10][seen[newtext[i+1]-'a']%10];
            cipher[i+1]=matrix[seen[newtext[i+1]-'a']/10][seen[newtext[i]-'a']%10];
        }
   }
   cipher[n]='\0';
    return cipher;
}

char * Decrypt(const char *key,char * cipher,char & filler){
    char matrix[5][5];
    int seen[26];
    memset(seen,-1,sizeof(seen));
    int k=0;
    int n=strlen(key);
    int a=0;
    //8,9 ie. i,j are the pairs
    for(int i=0;i<5;i++)
    {
        for(int j=0;j<5;j++)
        {
            if(k < n){
                while(seen[key[k]-'a']!=-1) k++;

                if(k < n){
                    if(key[k]=='i' || key[k]=='j') {
                        seen[8]=seen[9]=encode(i,j);
                    }
                    seen[key[k]-'a']=encode(i,j);
                    matrix[i][j]=key[k++];
                }
            }
            else{
                while(seen[a]!=-1) a++;
                if(a==8 || a==9) seen[8]=seen[9]=encode(i,j);
                seen[a]=encode(i,j);
                matrix[i][j]=char('a'+a);
            }
        }
    }
    n=strlen(cipher);
    char * plaintext=(char*)malloc(sizeof(char)*n);
    //reverse of encryption alphabetic pairs
    for(int i=0;i<n;i+=2)
   {
        if(check(seen[cipher[i]-'a'],seen[cipher[i+1]-'a'],'r')){
            plaintext[i]=(matrix[seen[cipher[i]-'a']/10][(5+seen[cipher[i]-'a']%10-1)%5]); //extraction of row and column and shifiting the column
            plaintext[i+1]=(matrix[seen[cipher[i+1]-'a']/10][(5+seen[cipher[i+1]-'a']%10-1)%5]);
        }
        else if(check(seen[cipher[i]-'a'],seen[cipher[i+1]-'a'],'c')){
            plaintext[i]=matrix[(5+seen[cipher[i]-'a']/10-1)%5][seen[cipher[i]-'a']%10];
            plaintext[i+1]=matrix[(5+seen[cipher[i+1]-'a']/10-1)%5][seen[cipher[i+1]-'a']%10];
        }
        else{
            plaintext[i]=matrix[seen[cipher[i]-'a']/10][seen[cipher[i+1]-'a']%10];
            plaintext[i+1]=matrix[seen[cipher[i+1]-'a']/10][seen[cipher[i]-'a']%10];
        }
   }
   plaintext[n]='\0';
   int j=0;
   for(int i=0;i< n;i++){ //remove filler
    if(plaintext[i] !=filler) cipher[j++]=plaintext[i];
   }
   cipher[j]='\0';
   return cipher;
}