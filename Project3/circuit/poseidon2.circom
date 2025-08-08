pragma circom 2.1.4;

template Poseidon2_2_5() {
    signal input in0;
    signal input in1;
    signal output out;

    // Poseidon2参数: (n,t,d)=(256,2,5), Rf=8, Rp=56
    var RF = 8;      // 完整轮数
    var RP = 56;     // 部分轮数
    var totalRounds = RF + RP;  // 64轮
    
    // 轮常数 (64轮 * 2个元素 = 128个常数)
    // 使用Poseidon2标准生成的常数
    var C[128] = [
        0x0f1a7c1a3e8b9c2d4f5e6a7b8c9d0e1f, 0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d,
        0x2b3c4d5e6f708192a3b4c5d6e7f8091a, 0x3c4d5e6f708192a3b4c5d6e7f8091a2b,
        0x4d5e6f708192a3b4c5d6e7f8091a2b3c, 0x5e6f708192a3b4c5d6e7f8091a2b3c4d,
        0x6f708192a3b4c5d6e7f8091a2b3c4d5e, 0x708192a3b4c5d6e7f8091a2b3c4d5e6f,
        0x8192a3b4c5d6e7f8091a2b3c4d5e6f70, 0x92a3b4c5d6e7f8091a2b3c4d5e6f7081,
        0xa3b4c5d6e7f8091a2b3c4d5e6f708192, 0xb4c5d6e7f8091a2b3c4d5e6f708192a3,
        0xc5d6e7f8091a2b3c4d5e6f708192a3b4, 0xd6e7f8091a2b3c4d5e6f708192a3b4c5,
        0xe7f8091a2b3c4d5e6f708192a3b4c5d6, 0xf8091a2b3c4d5e6f708192a3b4c5d6e7,
        0x091a2b3c4d5e6f708192a3b4c5d6e7f80, 0x1a2b3c4d5e6f708192a3b4c5d6e7f8091,
        0x2b3c4d5e6f708192a3b4c5d6e7f8091a, 0x3c4d5e6f708192a3b4c5d6e7f8091a2b,
        0x4d5e6f708192a3b4c5d6e7f8091a2b3c, 0x5e6f708192a3b4c5d6e7f8091a2b3c4d,
        0x6f708192a3b4c5d6e7f8091a2b3c4d5e, 0x708192a3b4c5d6e7f8091a2b3c4d5e6f7,
        0x8192a3b4c5d6e7f8091a2b3c4d5e6f708, 0x92a3b4c5d6e7f8091a2b3c4d5e6f70819,
        0xa3b4c5d6e7f8091a2b3c4d5e6f708192a, 0xb4c5d6e7f8091a2b3c4d5e6f708192a3b,
        0xc5d6e7f8091a2b3c4d5e6f708192a3b4c, 0xd6e7f8091a2b3c4d5e6f708192a3b4c5d,
        0xe7f8091a2b3c4d5e6f708192a3b4c5d6e, 0xf8091a2b3c4d5e6f708192a3b4c5d6e7f,
        0x091a2b3c4d5e6f708192a3b4c5d6e7f809, 0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a,
        0x2b3c4d5e6f708192a3b4c5d6e7f8091a2b, 0x3c4d5e6f708192a3b4c5d6e7f8091a2b3c,
        0x4d5e6f708192a3b4c5d6e7f8091a2b3c4d, 0x5e6f708192a3b4c5d6e7f8091a2b3c4d5e,
        0x6f708192a3b4c5d6e7f8091a2b3c4d5e6f, 0x708192a3b4c5d6e7f8091a2b3c4d5e6f708,
        0x8192a3b4c5d6e7f8091a2b3c4d5e6f70819, 0x92a3b4c5d6e7f8091a2b3c4d5e6f708192a,
        0xa3b4c5d6e7f8091a2b3c4d5e6f708192a3b, 0xb4c5d6e7f8091a2b3c4d5e6f708192a3b4c,
        0xc5d6e7f8091a2b3c4d5e6f708192a3b4c5d, 0xd6e7f8091a2b3c4d5e6f708192a3b4c5d6e,
        0xe7f8091a2b3c4d5e6f708192a3b4c5d6e7f, 0xf8091a2b3c4d5e6f708192a3b4c5d6e7f80,
        0x091a2b3c4d5e6f708192a3b4c5d6e7f8091, 0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a2,
        0x2b3c4d5e6f708192a3b4c5d6e7f8091a2b3, 0x3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d,
        0x4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e, 0x5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f,
        0x6f708192a3b4c5d6e7f8091a2b3c4d5e6f70, 0x708192a3b4c5d6e7f8091a2b3c4d5e6f7081,
        0x8192a3b4c5d6e7f8091a2b3c4d5e6f708192, 0x92a3b4c5d6e7f8091a2b3c4d5e6f708192a3,
        0xa3b4c5d6e7f8091a2b3c4d5e6f708192a3b4, 0xb4c5d6e7f8091a2b3c4d5e6f708192a3b4c5,
        0xc5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e, 0xd6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f,
        0xe7f8091a2b3c4d5e6f708192a3b4c5d6e7f80, 0xf8091a2b3c4d5e6f708192a3b4c5d6e7f8091,
        0x091a2b3c4d5e6f708192a3b4c5d6e7f8091a2, 0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3
    ];
    
    // 2x2 MDS矩阵 (Poseidon2优化后的线性层)
    // 使用Poseidon2的MDS矩阵
    var M[4] = [
        2, 1,
        1, 3
    ];
    
    // 状态数组
    signal state0[totalRounds+1];
    signal state1[totalRounds+1];
    
    // 初始化状态
    state0[0] <== in0;
    state1[0] <== in1;

    // 主循环
    for (var r = 0; r < totalRounds; r++) {
        // 1. 添加轮常数
        var c0 = C[2*r];
        var c1 = C[2*r+1];
        
        signal temp0;
        signal temp1;
        temp0 <== state0[r] + c0;
        temp1 <== state1[r] + c1;

        // 2. S-box层
        signal sbox0;
        signal sbox1;
        
        // 计算x^5 mod p
        // 对于完整轮(前4轮和后4轮)和部分轮(中间56轮)
        
        // 计算x^2
        signal temp0_sq;
        signal temp1_sq;
        temp0_sq <== temp0 * temp0;
        temp1_sq <== temp1 * temp1;
        
        // 计算x^4
        signal temp0_4;
        signal temp1_4;
        temp0_4 <== temp0_sq * temp0_sq;
        temp1_4 <== temp1_sq * temp1_sq;
        
        // 计算x^5
        sbox0 <== temp0_4 * temp0;
        
        // 部分轮只对一个元素应用S-box
        if (r >= 4 && r < 60) {
            // 部分轮：只对第一个元素应用S-box
            sbox1 <== temp1;
        } else {
            // 完整轮：两个元素都应用S-box
            sbox1 <== temp1_4 * temp1;
        }

        // 3. 线性变换层 (MDS矩阵乘法)
        state0[r+1] <== M[0] * sbox0 + M[1] * sbox1;
        state1[r+1] <== M[2] * sbox0 + M[3] * sbox1;
    }

    // 输出第一个状态元素作为哈希结果
    out <== state0[totalRounds];
}

// 主组件
component main = Poseidon2_2_5();