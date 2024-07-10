import { assert } from "chai";
import hre from "hardhat";

//facts about the bn254 curve, or helpful constants
export const field_order = BigInt(
  "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
);
export const field_order_minus_1_over_4 = BigInt(
  "0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52",
); //needed for exponentiation
export const ZERO = BigInt("0");
export const ONE = BigInt("1");
export const TWO = BigInt("2");

export function random_hex(v: number): string {
  return hre.ethers.hexlify(hre.ethers.randomBytes(v));
}

export function random_big(n: number): bigint {
  return BigInt(random_hex(n));
}

export function big_to_hex(n: bigint): string {
  return hre.ethers.zeroPadValue(n.toString(), 32);
}

export function random_element(): bigint {
  return random_big(32) % field_order;
}

export function random_hexed_element(): string {
  return big_to_hex(random_element());
}

export function exp(argument: bigint, exponent: bigint): bigint {
  let retval = 1n;
  let e_prime: bigint = exponent;
  let base: bigint = argument % field_order;
  while (e_prime > 0) {
    if (e_prime % 2n == 1n) {
      retval = (retval * base) % field_order;
    }
    e_prime = e_prime >> 1n;
    base = (base * base) % field_order;
  }
  return retval;
}

export function sqrt(argument: bigint): { retval: bigint; found: boolean } {
  const retval: bigint = exp(argument, field_order_minus_1_over_4);
  const found: boolean = (retval * retval) % field_order == argument;
  return { retval, found };
}

export function inverse(argument: bigint): bigint {
  //fermat's little theorem
  return exp(argument, field_order - TWO);
}

export function to_hex_string(n: bigint): `0x${string}` {
  return ("0x" + n.toString(16).padStart(64, "0")) as `0x${string}`;
}
//TSX version of the code https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/main/poc/hash_to_field.py
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
  const b0 = hre.ethers.keccak256(b_0);

  const b_i = hre.ethers.solidityPacked(
    ["bytes", "uint8", "bytes", "uint8"],
    [b0, 1, domain, domain.length],
  );
  let bi = hre.ethers.keccak256(b_i);

  const out = new Uint8Array(output_length);
  const ell = Math.ceil(output_length / 32);
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
  return out;
}
//https://datatracker.ietf.org/doc/html/rfc9380#name-hash_to_field-implementatio
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

    const tmp = BigInt(
      `0x${Array.from(tv)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("")}`,
    );
    const e = tmp % field_order;
    result.push(e);
  }

  return [result[0], result[1]];
}

describe("utils", function () {
  it("Sqrt should run", async function () {
    for (let i = 0; i < 100; ++i) {
      const a: bigint = random_element();
      const b: bigint = (a * a) % field_order;
      const result = sqrt(b);
      assert.isTrue(result.found);
      assert.isTrue((result.retval * result.retval) % field_order == b);
    }
  });

  it("Inverse should run", async function () {
    for (let i = 0; i < 100; ++i) {
      const a: bigint = random_element();
      const b: bigint = inverse(a);
      assert.isTrue((a * b) % field_order == ONE);
    }
  });
});
