# solbls

This is a basic implementation of BN254 in Solidity. The library copied here is from [kevincharm](https://github.com/kevincharm/bls-bn254/tree/master)'s version, but actually this is a massive amalgamation of the following repos / exists in many versions, all of which seem to be based on [this article](https://ethresear.ch/t/bls-signatures-in-solidity/7919):

- https://gist.github.com/kobigurk/257c1783ddf556e330f31ed57febc1d9
- https://github.com/ralexstokes/deposit-verifier/blob/8da90a8f6fc686ab97506fd0d84568308b72f133/deposit_verifier.sol
- https://github.com/kilic/evmbls/blob/master/contracts/BLS.sol
- https://github.com/thehubbleproject/hubble-contracts


All in all, the contract performs well according to [RFC 9380](https://datatracker.ietf.org/doc/html/rfc9380). It implements the recommended `expand_msg_xmd` algorithm for hashing a bytestring to an element of the field, and likewise hashing a bytestring to a pair of elements in the field. To convert these field elements to curve elements, it implements the Shallue-van de Woestijne-Ulas algorithm, which is constant time, and relatively cheap to execute on-chain.

This is a big difference from the other versions which implement either Fouque-Tibouchi (FT) or the try-and-increment / hash-and-pray. The problem with FT and hash-and-pray is the fact that they are not constant time algorithms, and each iteration is expensive enough so that a bad actor can produce a message that's too expensive to check on-chain. The Hubble project quantified the expense of these algorithms to be about ~30k gas. One of the most expensive steps in hash-and-pray is the sqrt step, which takes 14k gas alone by calling the modexp precompile. This is why all of these versions have ported a copy of the [ModExp.sol library](https://github.com/ChihChengLiang/modexp/blob/master/contracts/ModExp.sol), which reduces the gas used to about 7k gas. The current version using SvdW is constant-time, and reasonably cheap, at the cost of being difficult to implement.

This version of the contract does not implement point compression, or subgroup membership. The point compression only impacts the gas used in the transaction / memory required to store signatures and keys. However, the subgroup membership checks are, in general, a security vulnerability.

For BN254, the smallest $r$-order cyclic subgroup in $E(\mathbb{F}_p)$ is simply the curve itself / the $r$-torsion, namely $\mathbb{G}_1=[r]E(\mathbb{F}_p)=E(\mathbb{F}_p)$. However, this is not the case for $\mathbb{G} _2$, and so valid public keys must be checked against the subgroup of the elliptic curve field, namely $\mathbb{G} _2=[r]E^\prime(\mathbb{F} _{p^2})\subset E^\prime(\mathbb{F} _{p^2})$. Look [here](https://github.com/warlock-labs/alt-bn128-bls/blob/main/notebooks/field_extensions.ipynb) for details on these membership checks.
These attacks would allow a bad actor to use a false public key to verify signatures.

The likelihood of this attack is inversely proportional to the magnitude of the smallest prime factor of the $\mathbb{G} _2$ cofactor. Successful small group attacks are much more likely for cofactors on the order of 1-10. For BN254, $|E^\prime(\mathbb{F} _{p^2})| = c _2r$, where
```python
c_2 = 21888242871839275222246405745257275088844257914179612981679871602714643921549
```
which has the following factorization:
```
10069 * 5864401 * 1875725156269 * 197620364512881247228717050342013327560683201906968909
```
Notice that the smallest prime factor is "large" compared to the order of magnitude needed for the attack. Therefore, BN254 is relatively secuer against these subgroup attacks contingent on the lifetime of valid public keys.

Further, while being relatively safe on BN254, $\mathbb{G} _2$ operations, including twist operations, are extremely expensive to compute on chain, which is probably the bigger reason why they are not implemented. [Current versions](https://github.com/musalbas/solidity-BN256G2) report that the estimated gas for addition and multiplication in $\mathbb{G} _2$ are 30k gas, and 2M gas respectively (!).

### Test results

The following hashing utility functions of the library are compared against implementations written in TSX:

- `expandMsgTo96`: this hashes a bytestring to an element of the desired base field
- `hashToField`: this takes a bytestring and returns a pair of elements in the base field
    - each of these elements is then mapped to a point on the curve via SvdW, and then added to produce a hash on the curve

The above tests check random messages of lengths ranging from 10 to 256 bytes. 

---

The following cryptographic functions of the library are compared against implementations in Sage, which is used to produce reference data of inputs and outputs for the various operations:

- `isValidSignature`: this determines if a signature is indeed a point on $\mathbb{G} _1=[r]E(\mathbb{F} _p)$ 
- `isValidPublicKey`: this determines if a signature is indeed a point on $\mathbb{G} _2=[r]E^\prime(\mathbb{F} _{p^2})$
- `mapToPoint`: this is the implementation of the SvdW algorithm taking an element of the base field, and producing a point on the curve $E(\mathbb{F}_p)$. 
- `verifySingle`: this is what actually calls the SNARK precompile to determine the validity of the pairing checks for a given hashed message, signature, and public key.

The above tests uses a set of 1000 (input, output) pairs.

To generate the reference set:
```bash
cd test/sage_reference
make
sage generate_refs.sage
```
which outputs the data into `bn254_reference.json`. 

To conduct the tests, in the home directory, simply execute:

```bash
npm i --force
npx hardhat compile 
npx hardhat test
```

---

The tests also measure the gas per method call from the contract. From a black box perspective, the hash functions especially should run constant time, which we verify with the low variation across the costs for messages of varying byte lengths. All tests have low variation across inputs, and the most expensive is (understandably) the final exponentiation / pairing step at the end which verifies signatures.

All tests pass, except the subgroup membership checks, which is to be expected. Units are gwei.

![test results](/test/test_results.png)

