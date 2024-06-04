
# 第1步: 安装Rust环境
参考: https://www.sysgeek.cn/ubuntu-install-rust/ 

rust下载太慢, 更换国内源

参考: https://www.cnblogs.com/hustcpp/p/12341098.html

步骤: bash rust.sh

报错: curl: (1) Protocol "http" not supported or disabled in libcurl
rustup: command failed: downloader http://mirrors.ustc.edu.cn/rust-static/rustup/dist/x86_64-unknown-linux-gnu/rustup-init /tmp/tmp.KAZeUThC05/rustup-init x86_64-unknown-linux-gnu

修正: 将http改为https

步骤: :echo "RUSTUP_DIST_SERVER=https://mirrors.tuna.tsinghua.edu.cn/rustup"  >> ~./ .cargo/env  

报错: bash: ~./: Is a directory

修正: 文件改为$HOME/.cargo/env

新建一个终端(必须要新建一个才有. ), 然后运行hello实例

cargo new hello

cd hello

cargo run

运行成功即安装好了rust环境. 

# 第2步 运行程序
cargo build --release

cargo run --release 0 ./data/heart_11bits 10

cargo run --release 0 ./data/breast_11bits 10

cargo run --release 0 ./data/spam_11bits 10

cargo run --release 0 ./data/steel_11bits 10

cargo run --release 1 ./data/network_8width 10

cargo run --release 1 ./data/network_16width 10

cargo run --release 1 ./data/network_breast_11bits_7depth_16width 10

cargo run --release 1 ./data/network_heart_11bits_3depth_8width 10

有点疑惑的位置cargo build --release中fftw的时间很长. 

Building [=======================>   ] 73/79: concrete-fftw-sys(build) 

# 第3步 代码的解释

1. 该目录下主要有data和src两个文件夹:

    data文件夹中有tree和network的测试用例, 用于测试. 

    src文件夹中有包含项目的所有代码, 其中main.rs是入口. 

2. 在src/main.rs的main函数中:

    有3个输入: 分别是choice为0运行cipher_tree(), 为1运行cipher_network(). 

    cipher_tree()是对data文件夹中tree进行加密, 然后再密态tree上进行数据评估. 

    cipher_network()是对data文件夹中network进行加密, 然后再密态network上进行数据评估. 

3. 函数中有大量输出, 必要时可以删去. 

4. 未完成的工作:

    密态模型的导入导出问题, 秘钥的导入导出问题.
    
    通信量的自动计算, 一个RLWE密文大概88KB.
    











# 致谢
Thanks the https://github.com/KULeuven-COSIC/SortingHat.git 
We use some function of rgsw and rlwe in their program.
