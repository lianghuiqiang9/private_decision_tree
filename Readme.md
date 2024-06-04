
# Model process
This is a two-party dense state model, the server and the client. 
1. The server sends the decision tree cipher to the client, 
2. The client uses it in the dense state decision tree, then the plaintext data is evaluated, and a ciphertext result is returned and sent to the server. 
3. The server gets the ciphertext result, and decrypts it with the private key to get the evaluation result.


# 1. should install "gmp-6.3.0" && "ntl-11.5.1"
参考：https://blog.csdn.net/weixin_45599342/article/details/121293041 

安装ntl报错：bash: ./configure: No such file or directory
修正：cd src

    g++ ntl_test.cpp -o ntl_test -lntl -pthread -lgmp
    ./ntl_test

if pass, the "GMP", "NTL" is successful instal.

# 2. should install "fftw3"
参考：sudo apt-get install libfftw3-dev

    g++ fftw3-test.cpp -o fftw3-test -lfftw3
    ./fftw3-test 

if pass, the "fftw3" is successful instal.

# 3. then instal "final", in the final file

    cd final
    make 
    cd ..
    g++ -o lwe_fhe_test lwe_fhe_test.cpp -O3 -I final final/libfinal.a -lntl -lgmp -lfftw3 -lm
    ./lwe_fhe_test

if pass, the "final" is successful instal.

# 4. then compile the cdte

    g++ -o cdte cdte.cpp src/utils.cpp src/node.cpp -O3 -I./include -I final final/libfinal.a -lntl -lgmp -lfftw3 -lm 
    ./cdte

# 5. The FINAL library used here, because there is addition, which can reduce a lot of operations.

# 代码解释
该代码使用全同态加密库FINAL，对tree进行二进制加密，然后再加密tree上进行全路径遍历的到评估结果。