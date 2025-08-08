const chai = require("chai");
const wasm_tester = require("circom_tester").wasm;
const path = require("path");

describe("Poseidon2_2_5 测试", function () {
  this.timeout(100000);
  
  let circuit;
  
  before(async () => {
    circuit = await wasm_tester(
      path.join(__dirname, "../circuit/main.circom")
    );
  });

  it("应正确计算哈希", async () => {
    const input = {
      in0: "12345678901234567890123456789012",
      in1: "98765432109876543210987654321098"
    };
    
    const witness = await circuit.calculateWitness(input);
    await circuit.assertOut(witness, { out: "预期哈希值" }); // 替换为实际值
    console.log("哈希值:", witness[1]);
  });
});