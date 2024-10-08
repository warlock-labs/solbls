## Initial audit

All in all, the contract performs well according to [RFC 9380](https://datatracker.ietf.org/doc/html/rfc9380). It
implements the recommended `expand_msg_xmd` algorithm for hashing a bytestring to an element of the field, and likewise
hashing a bytestring to a pair of elements in the field. To convert these field elements to curve elements, it
implements the Shallue-van de Woestijne encoding, which is constant time, and relatively cheap to execute on-chain.

This is a big difference from the other versions which implement either Fouque-Tibouchi (FT) or the try-and-increment /
hash-and-pray. The problem with FT and hash-and-pray is the fact that they are not constant time algorithms, and each
iteration is expensive enough so that a bad actor can produce a message that's too expensive to check on-chain. The
Hubble project quantified the expense of these algorithms to be about ~30k gas. One of the most expensive steps in
hash-and-pray is the sqrt step, which takes 14k gas alone by calling the modexp precompile. This is why all of these
versions have ported a copy of
the [ModExp.sol library](https://github.com/ChihChengLiang/modexp/blob/master/contracts/ModExp.sol), which reduces the
gas used to about 7k gas. The current version using SvdW is constant-time, and reasonably cheap, at the cost of being
difficult to implement.

This version of the contract does not implement point compression, or subgroup membership. The point compression only
impacts the gas used in the transaction / memory required to store signatures and keys. However, the subgroup membership
checks are, in general, a security vulnerability.

### Subgroup membership checks

For BN254, the smallest $r$-order cyclic subgroup in $E(\mathbb{F}_p)$ is simply the curve itself / the $r$-torsion,
namely $\mathbb{G}_1=[r]E(\mathbb{F}_p)=E(\mathbb{F}_p)$. However, this is not the case for $\mathbb{G} _2$, and so
valid public keys must be checked against the subgroup of the elliptic curve field, namely $\mathbb{G} _2=[r]E^\prime(
\mathbb{F} _{p^2})\subset E^\prime(\mathbb{F} _{p^2})$.
Look [here](https://github.com/warlock-labs/alt-bn128-bls/blob/main/notebooks/field_extensions.ipynb) for details on
these membership checks.
These attacks would allow a bad actor to use a false public key to verify signatures.

The likelihood of this attack is inversely proportional to the magnitude of the smallest prime factor of the
$\mathbb{G} _2$ cofactor. Successful small group attacks are much more likely for cofactors on the order of 1-10. For
BN254, $|E^\prime(\mathbb{F} _{p^2})| = c _2r$, where

```python
c_2 = 21888242871839275222246405745257275088844257914179612981679871602714643921549
```

which has the following factorization:

```
10069 * 5864401 * 1875725156269 * 197620364512881247228717050342013327560683201906968909
```

In this case, a false key would need to be of order 10069. The subgroup check, despite in not being explicitly
implemented in the Solidity, is still caught eventually by the precompile at `0x08` which executes the pairing
operation. The cryptography backend takes the bytes from Solidity, and after deserialization performs curve and subgroup
membership checks, which then ultimately rejects malformed public keys. The reliance on the precompile to catch these
malformed keys may, or may not, have been intentional from the original Solidity, but that is unclear at this time.

Further, while being relatively safe on BN254, $\mathbb{G} _2$ operations, including twist operations, are extremely
expensive to compute on chain, which is probably the bigger reason why they are not
implemented. [Current versions](https://github.com/musalbas/solidity-BN256G2) report that the estimated gas for addition
and multiplication in $\mathbb{G} _2$ are 30k gas, and 2M gas respectively (!), so if nothing else, the subgroup checks
were most likely cut for costs.

There is a breakdown of some more efficient ways to perform the check here:
https://ethresear.ch/t/fast-mathbb-g-2-subgroup-check-in-bn254/13974

Where the state-of-the-art is reduced to 1M gas, and thus still not feasible to perform on-chain

## Test results

The following hashing utility functions of the library are compared against implementations written in Foundry:

- `expandMsgTo96`: this hashes a bytestring to an element of the desired base field
- `hashToField`: this takes a bytestring and returns a pair of elements in the base field
    - each of these elements is then mapped to a point on the curve via SvdW, and then added to produce a hash on the
      curve

The above tests check random messages of ranging lengths.

The following cryptographic functions of the library are compared against implementations in Sage, which is used to
produce reference data of inputs and outputs for the various operations:

- `isValidSignature`: this determines if a signature is indeed a point on $\mathbb{G} _1=[r]E(\mathbb{F} _p)$
- `isValidPublicKey`: this determines if a signature is indeed a point on $\mathbb{G} _2=[r]E^\prime(\mathbb{F} _{p^2})$
- `mapToPoint`: this is the implementation of the SvdW algorithm taking an element of the base field, and producing a
  point on the curve $E(\mathbb{F}_p)$.
- `verifySingle`: this is what actually calls the SNARK precompile to determine the validity of the pairing checks for a
  given hashed message, signature, and public key.

The above tests uses a set of 1000 (input, output) pairs. To generate the reference set:

```bash
cd test/sage_reference
make
sage generate_refs.sage
```

which outputs the data into `bn254_reference_transformed.json`.

To conduct the tests, in the home directory, simply execute:

```bash
forge test -vvv
```

---
All tests pass, except the subgroup membership checks, which is to be expected. Units are gwei. `testFail_E2noG2()` does
not actually use that much gas. It fails instantly.

![test results](/test/test_results.png)