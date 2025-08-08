#!/bin/bash

# 1. 生成参数
node generate_params.js

# 2. 插入参数到电路
cat circuit/poseidon2.circom | \
  awk '/\/\/ PARAMS_PLACEHOLDER/{system("cat circuit/params.inc");next}1' \
  > circuit/poseidon2_temp.circom
mv circuit/poseidon2_temp.circom circuit/poseidon2.circom

# 3. 编译电路
circom circuit/main.circom --r1cs --wasm --sym -o build

# 4. 生成Groth16参数
snarkjs groth16 setup build/main.r1cs pot12_final.ptau build/circuit.zkey
snarkjs zkey export verificationkey build/circuit.zkey build/verification_key.json

echo "编译完成！电路文件在 build 目录"