import { assert } from "chai";
import hre from "hardhat";

export const field_order = BigInt(
  "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
);
export function to_hex_string(n: bigint): `0x${string}` {
  return ("0x" + n.toString(16).padStart(64, "0")) as `0x${string}`;
}
export function hash_to_field(
  domain: Uint8Array,
  message: Uint8Array,
): [bigint, bigint] {
  const count = 2;
  const L = 48;
  const len_in_bytes = count * L;

  const exp_msg = expand_message(domain, message, len_in_bytes);

  const result: bigint[] = [];
  for (let i = 0; i < count; i++) {
    const elm_offset = L * i;

    const tv = exp_msg.slice(elm_offset, elm_offset + L);
    console.log(tv);
    const tmp = BigInt(
      `0x${Array.from(tv)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("")}`,
    );
    console.log(tmp);
    const e = tmp % field_order;
    console.log(e);
    result.push(e);
  }
  console.log(result);
  return [result[0], result[1]];
}

export function expand_message(
  domain: Uint8Array,
  message: Uint8Array,
  output_length: number,
): Uint8Array {
  if (domain.length > 255) {
    throw new Error("bad domain size");
  }

  const domainLen = domain.length;
  if (domainLen > 255) {
    throw new Error("InvalidDSTLength");
  }

  const zpad = new Uint8Array(136);
  //console.log(zpad, message, "BitShift:",output_length >> 8,"BitAnd:",output_length & 0xff,0,"domain:",domain,"domainLen",domainLen);
  const b_0 = hre.ethers.solidityPacked(
    ["bytes", "bytes", "uint8", "uint8", "uint8", "bytes", "uint8"],
    [
      zpad,
      message,
      output_length >> 8,
      output_length & 0xff,
      0,
      domain,
      domainLen,
    ],
  );
  //console.log("packedSol",b_0);
  const b0 = hre.ethers.keccak256(b_0);
  //console.log("hashed",b0);
  const b_i = hre.ethers.solidityPacked(
    ["bytes", "uint8", "bytes", "uint8"],
    [b0, 1, domain, domain.length],
  );
  let bi = hre.ethers.keccak256(b_i);
  //console.log("hashed2",bi);
  const out = new Uint8Array(output_length);
  const ell = Math.ceil(output_length / 32);
  //console.log("At For Loop");
  for (let i = 1; i <= ell; i++) {
    const bi_bytes = hre.ethers.getBytes(bi);
    const copyLength = Math.min(32, output_length - (i - 1) * 32);
    out.set(bi_bytes.slice(0, copyLength), (i - 1) * 32);

    if (i < ell) {
      const b_i = hre.ethers.solidityPacked(
        ["bytes32", "uint8", "bytes", "uint8"],
        [to_hex_string(BigInt(b0) ^ BigInt(bi)), i + 1, domain, domain.length],
      );
      bi = hre.ethers.keccak256(b_i);
    }
  }
  //console.log(out);
  return out;
}
