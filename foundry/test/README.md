### Foundry Re-write Of SolBLS Tests
This section of the repo contains a Foundry re-write of the `BLS.ts`
hardhat script.

It runs the same tests as it, on identical data. It just uses Solidity
instead of Typescript.

In its current iteration, it fails assertion tests in `testLibraryConsistent()`, the
second that it sees `G2_public_key[0]`.

This is concerning, I think, because `testLibConsistent2()` uses an identical algorithm
over the `e2_non_g2`, and behaves correctly.

All other tests provide the expected behavior.

<img width="1437" alt="Screenshot 2024-07-20 at 11 14 14 AM" src="https://github.com/user-attachments/assets/33a84efa-428c-47c8-a0eb-224c5d46a4c4">
