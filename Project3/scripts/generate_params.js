const { generatePoseidonParams } = require("circomlib/src/poseidon_slow.js");
const F = require("circomlib/src/eddsa.js").babyJub.F;
const fs = require("fs");

const params = generatePoseidonParams({
  F: F,
  t: 2,              // 状态元素数量
  fullRounds: 8,      // Rf
  partialRounds: 56,  // Rp
  sboxPower: 5        // S-box指数
});

// 展平轮常数
const roundConstants = [];
for (let i = 0; i < params.roundConstants.length; i++) {
  roundConstants.push(...params.roundConstants[i]);
}

// 展平MDS矩阵
const mdsFlat = [];
for (let i = 0; i < params.mdsMatrix.length; i++) {
  mdsFlat.push(...params.mdsMatrix[i]);
}

// 生成Circom代码
const code = `
  var C[128] = [${roundConstants.join(",\n")}];
  var M[4] = [${mdsFlat.join(",\n")}];
`;

fs.writeFileSync("../circuit/params.inc", code);
console.log("参数已生成到 circuit/params.inc");