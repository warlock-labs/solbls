import { expect, assert } from "chai";
import hre from "hardhat";
import { BLSTest, BLSTest__factory } from "../typechain-types";
import { expand_message, hash_to_field } from "./utils";
import { ContractTransaction, randomBytes, toUtf8Bytes } from "ethers";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import fs from "fs";
import path from "path";

function nth_root(value: bigint, k = 2n) {
  if (value < 0n) {
    throw "negative number is not supported";
  }

  let o = 0n;
  let x = value;
  let limit = 100n;

  while (x ** k !== k && x !== o && --limit) {
    o = x;
    x = ((k - 1n) * x + value / x ** (k - 1n)) / k;
  }

  return x;
}

function report_cost(fname: string, costs: bigint[]) {
  if (costs.length === 0) {
    return;
  }
  const avg: bigint =
    costs.reduce((a: bigint, b: bigint) => {
      return a + b;
    }, 0n) / BigInt(costs.length);

  const variance =
    costs
      .map(cost => {
        const diff = cost - avg;
        return diff * diff;
      })
      .reduce((a, b) => a + b, 0n) / BigInt(costs.length);

  const std_dev = nth_root(variance);
  console.log("\nAverage %s cost: %s", fname, hre.ethers.formatUnits(avg,9));

  console.log(
    "\n\tVariation in %s cost: %s\n",
    fname,
    hre.ethers.formatUnits(std_dev,9),
  );
}
interface G1Affine {
  x: string;
  y: string;
}

interface G2Affine {
  x: { c0: string; c1: string };
  y: { c0: string; c1: string };
}

interface SVDW {
  i: string;
  x: string;
  y: string;
}

const reference_data = JSON.parse(
  fs.readFileSync(
    path.resolve("./test/sage_reference/bn254_reference.json"),
    "utf-8",
  ),
);
const g1_points = reference_data.G1_signatures.map(convertG1Point);
const g2_points = reference_data.G2_public_keys.map(convertG2Point);
const e2_non_g2_points = reference_data.E2_non_G2.map(convertG2Point);
const svdw_points = reference_data.svdw.map(convertSVDW);
const domain = "BLS_SIG_BN254G1_XMD:KECCAK-256_SSWU_RO_NUL_";

function convertG1Point(point: G1Affine): [bigint, bigint] {
  return [BigInt(point.x), BigInt(point.y)];
}

function convertG2Point(point: G2Affine): [bigint, bigint, bigint, bigint] {
  return [
    BigInt(point.x.c0),
    BigInt(point.x.c1),
    BigInt(point.y.c0),
    BigInt(point.y.c1),
  ];
}

function convertSVDW(point: SVDW): [bigint, bigint, bigint] {
  return [BigInt(point.i), BigInt(point.x), BigInt(point.y)];
}
async function format_estimated_gas(gas: bigint): Promise<bigint> {
  const fee_data = await hre.ethers.provider.getFeeData();
  return fee_data.maxFeePerGas
    ? gas * fee_data.maxFeePerGas
    : !fee_data.maxFeePerGas && fee_data.gasPrice
      ? gas * fee_data.gasPrice
      : 0n;
}

describe("BLS", function () {
  let bls: BLSTest;
  let owner: SignerWithAddress;
  let deployment_costs: bigint[] = [];
  let exp_msg_costs: bigint[] = [];
  let hash2field_costs: bigint[] = [];
  let g1_costs: bigint[] = [];
  let g2_costs: bigint[] = [];
  let e2_non_g2_costs: bigint[] = [];
  let svdw_costs: bigint[] = [];
  let verify_costs: bigint[] = [];

  async function send_and_get_cost_from_tx(
    tx: ContractTransaction,
  ): Promise<[string, bigint]> {
    tx.from = await owner.getAddress();
    if (!tx.gasLimit) {
      tx.gasLimit = await owner.estimateGas(tx);
    }
    const response = await owner.call(tx);

    const txx = await owner.sendTransaction(tx);
    const receipt = await txx.wait();

    const gas_used = receipt?.gasUsed!;
    return [response, gas_used * receipt?.gasPrice!];
  }

  this.beforeEach(async function () {
    [owner] = await hre.ethers.getSigners();
    const bls_factory = new BLSTest__factory(owner);
    const deploy_tx = await bls_factory.getDeployTransaction();
    const estimated_gas = await owner.estimateGas(deploy_tx);
    const deployment_cost = await format_estimated_gas(estimated_gas);

    bls = await bls_factory.deploy();
    await bls.waitForDeployment();

    const receipt = await bls.deploymentTransaction()?.wait();
    const cost = receipt?.gasUsed! * receipt?.gasPrice!;
    deployment_costs.push(cost);
  });

  this.afterAll(async function () {
    report_cost("deployment", deployment_costs);
    report_cost("expandMsgTo96", exp_msg_costs);
    report_cost("hashToField", hash2field_costs);
    report_cost("isValidSignature", g1_costs);
    report_cost("isValidPublicKey", g2_costs);
    report_cost("G2 exclusion checks", e2_non_g2_costs);
    report_cost("SvdW", svdw_costs);
    report_cost("verifySingle", verify_costs);
  });

  it("Hashing string to element of the field should work", async function () {
    for (let msg_len = 10; msg_len < 256; ++msg_len) {
      const message = randomBytes(msg_len);
      const txo = await bls.expandMsgTo96.populateTransaction(
        toUtf8Bytes(domain),
        message,
      );
      const [response, cost] = await send_and_get_cost_from_tx(txo);
      const lhs = bls.interface
        .decodeFunctionResult("expandMsgTo96", response)[0]
        .toString();
      const rhs0 = expand_message(toUtf8Bytes(domain), message, 96);
      const rhs = `0x${Array.from(rhs0)
        .map(b => b.toString(16).padStart(2, "0"))
        .join("")}`;
      assert.isTrue(lhs == rhs);
      exp_msg_costs.push(cost);
    }
  });
  it("Hashing string to two elements of the field should work", async function () {
    for (let msg_len = 10; msg_len < 256; ++msg_len) {
      const message = randomBytes(msg_len);
      const txo = await bls.hashToField.populateTransaction(
        toUtf8Bytes(domain),
        message,
      );
      const [response, cost] = await send_and_get_cost_from_tx(txo);

      const _lhs = bls.interface
        .decodeFunctionResult("hashToField", response)[0]
        .toString()
        .split(",");
      const lhs: [bigint, bigint] = [BigInt(_lhs[0]), BigInt(_lhs[1])];

      const rhs = hash_to_field(toUtf8Bytes(domain), message);
      assert.isTrue(lhs[0] == rhs[0]);
      assert.isTrue(lhs[1] == rhs[1]);
      hash2field_costs.push(cost);
    }
  });
  it("Check that G1=[r]E(Fp) reference points are correctly accepted as signatures", async function () {
    await Promise.all(
      g1_points.map(async (point: [bigint, bigint]) => {
        const txo = await bls.isValidSignature.populateTransaction(point);
        const [response, cost] = await send_and_get_cost_from_tx(txo);
        const is_valid_sig = Boolean(
          bls.interface
            .decodeFunctionResult("isValidSignature", response)[0]
            .toString(),
        );
        expect(is_valid_sig).to.be.true;
        g1_costs.push(cost);
      }),
    );
  });
  it("Check that G2=[r]E'(Fp2) reference points are correctly accepted as pubkeys", async function () {
    await Promise.all(
      g2_points.map(async (point: [bigint, bigint, bigint, bigint]) => {
        const txo = await bls.isValidPublicKey.populateTransaction(point);
        const [response, cost] = await send_and_get_cost_from_tx(txo);
        const is_valid_pubkey = Boolean(
          bls.interface
            .decodeFunctionResult("isValidPublicKey", response)[0]
            .toString(),
        );
        expect(is_valid_pubkey).to.be.true;
        g2_costs.push(cost);
      }),
    );
  });
  it("Check that E'(Fp2) reference points that are not in the r-torsion are correctly rejected from G2", async function () {
    await Promise.all(
      e2_non_g2_points.map(async (point: [bigint, bigint, bigint, bigint]) => {
        const txo = await bls.isValidPublicKey.populateTransaction(point);
        const [response, cost] = await send_and_get_cost_from_tx(txo);
        const is_valid_pubkey = Boolean(
          bls.interface
            .decodeFunctionResult("isValidPublicKey", response)[0]
            .toString(),
        );
        expect(is_valid_pubkey).to.be.false;
        e2_non_g2_costs.push(cost);
      }),
    );
  });
  it("Verify SVDW implementation", async function () {
    await Promise.all(
      svdw_points.map(async (point: [bigint, bigint, bigint]) => {
        const txo = await bls.mapToPoint.populateTransaction(point[0]);
        const [response, cost] = await send_and_get_cost_from_tx(txo);
        const _target = bls.interface
          .decodeFunctionResult("mapToPoint", response)[0]
          .toString()
          .split(",");
        const target: [bigint, bigint] = [
          BigInt(_target[0]),
          BigInt(_target[1]),
        ];

        const is_on_g1 = await bls.isOnCurveG1(target);
        expect(is_on_g1).to.be.true;
        expect(target[0]).to.be.eq(point[1]);
        expect(target[1]).to.be.eq(point[2]);
        svdw_costs.push(cost);
      }),
    );
  });
  it("Check internal consistency of the library", async function () {
    const _hashed_message = await bls.hashToPoint(
      toUtf8Bytes(domain),
      toUtf8Bytes("Hello world!"),
    );
    //values above get returned as read-only arrays, need to copy
    const hashed_message: [bigint, bigint] = [..._hashed_message] as [
      bigint,
      bigint,
    ];
    const is_valid_message = await bls.isOnCurveG1(hashed_message);
    expect(is_valid_message).to.be.true;

    await Promise.all(
      g1_points.map(async (signature: [bigint, bigint], index: number) => {
        const pub_key = g2_points[index];
        const is_valid_pubkey = await bls.isValidPublicKey(pub_key);
        const is_valid_sig = await bls.isValidSignature(signature);
        expect(is_valid_pubkey).to.be.true;
        expect(is_valid_sig).to.be.true;
        const txo = await bls.verifySingle.populateTransaction(
          signature,
          pub_key,
          hashed_message,
        );
        const [response, cost] = await send_and_get_cost_from_tx(txo);
        const _verified = bls.interface
          .decodeFunctionResult("mapToPoint", response)[0]
          .toString()
          .split(",");
        const verified: {
          pairingSuccess: boolean;
          callSuccess: boolean;
        } = {
          pairingSuccess: Boolean(_verified[0]),
          callSuccess: Boolean(_verified[1]),
        };

        if (verified.callSuccess) {
          expect(verified.pairingSuccess).to.be.true;
          verify_costs.push(cost);
        }
      }),
    );

    await Promise.all(
      g1_points.map(async (signature: [bigint, bigint], index: number) => {
        const pub_key = e2_non_g2_points[index];
        const is_valid_pubkey = await bls.isValidPublicKey(pub_key);
        const is_valid_sig = await bls.isValidSignature(signature);
        expect(is_valid_pubkey).to.be.true;
        expect(is_valid_sig).to.be.true;
        const verified = await bls.verifySingle(
          signature,
          pub_key,
          hashed_message,
        );
        if (verified.callSuccess) {
          expect(verified.pairingSuccess).to.be.true;
        }
      }),
    );
  });
});
