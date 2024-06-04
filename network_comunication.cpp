#include<iostream>

using namespace std;



int main(){
    int depth = 5;
    int data_len =11;
    int leaf_len =5;
    int data_num =33;
    int logwidth =3;
    int width = (1<<logwidth);
    int RLWE =88;
    int RGSW = 8 * RLWE;
    int a,b;
    a=(width-1)*data_num*7*RLWE;
    a=a+ (depth -logwidth)*width *data_num*7*RLWE;
    a=a+ (depth -logwidth)*leaf_len*RGSW;
    a=a+ (depth -logwidth)*RGSW;
    a=a+ (depth -logwidth)*width *RGSW;

    b= (width-1) *leaf_len*RGSW;
    b=b+ (width-1) *2 *RGSW;
    b=b+ (width-1)*width*RGSW;
    b=b+ (depth - logwidth)*RGSW;

    cout<<a<<endl;
    cout<<b<<endl;
    cout<<a+b<<endl;


}