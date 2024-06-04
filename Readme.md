
# 1. 模型流程

这是一个两方密态模型, 服务器和客户端. 

1. 服务器将决策树加密发送给客户端.

2. 客户端在密态决策树用明文数据进行评估, 返回一个密文结果发送给服务器. 

3. 服务器得到密文结果用私钥解密得到评估结果. 

# 2. 需要安装的库 "OpenFHE"
首先要按照OpenFHE的官方指导https://github.com/openfheorg/openfhe-development 安装. 

    sudo apt-get install cmake
    sudo apt-get install clang
    sudo apt-get install libomp5
    sudo apt-get install libomp-dev
    sudo apt-get install autoconf
    export CC=/usr/bin/clang-11
    export CXX=/usr/bin/clang++-11
    
    git clone https://github.com/openfheorg/openfhe-development.git
    cd openfhe-development/

    mkdir build
    cd build
    cmake ..  -BUILD_STATIC=OFF
    make
    sudo make install


# 3. 编译运行

设置路径

    export LD_LIBRARY_PATH=/usr/local/lib

主要由GroupComp_main.cpp SingleComp_main.cpp MainWithSerial.cpp三个文件. 

    g++ -o GroupComp_main GroupComp_main.cpp src/utils.cpp src/node.cpp src/function.cpp -O3 -I ./include -I /usr/local/include/openfhe -I /usr/local/include/openfhe/core -I /usr/local/include/openfhe/pke -I /usr/local/include/openfhe/binfhe -I /usr/local/include/openfhe/cereal -L /usr/local/lib -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -fopenmp 
    ./GroupComp_main

    g++ -o SingleComp_main SingleComp_main.cpp src/utils.cpp src/node.cpp src/function.cpp -O3 -I ./include -I /usr/local/include/openfhe -I /usr/local/include/openfhe/core -I /usr/local/include/openfhe/pke -I /usr/local/include/openfhe/binfhe -I /usr/local/include/openfhe/cereal -L /usr/local/lib -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -fopenmp 
    ./SingleComp_main

    g++ -o MainWithSerial MainWithSerial.cpp src/serial.cpp src/utils.cpp src/node.cpp src/function.cpp -O3 -I ./include -I /usr/local/include/openfhe -I /usr/local/include/openfhe/core -I /usr/local/include/openfhe/pke -I /usr/local/include/openfhe/binfhe -I /usr/local/include/openfhe/cereal -L /usr/local/lib -lOPENFHEcore -lOPENFHEpke -lOPENFHEbinfhe -fopenmp 
    ./MainWithSerial

# 4. 密钥序列化

序列化和逆序列化时间在80s,87s左右. 并且我们进行了压缩处理. 使用了tar命令. 但是压缩和解压缩时间为20s左右吧（未计算）. 