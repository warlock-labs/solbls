def attack_risk(E1, E2, r):
    cofactor_E1 = E1.order() // r
    cofactor_E2 = E2.order() // r

    print(f"G1 cofactor:\t{cofactor_E1}")
    print(f"G2 cofactor:\t{cofactor_E2}")

    print(f"In order to small subgroup attack, the bad actor must do the following:\n\t- find a point `P` on E'(Fp2) that is not in [r]E'(Fp2)\n\t- find a small prime factor `h` of the G2 cofactor\n\t- use this small cofactor and a public key such that `hP` is in the torsion")

    print(r'This is usually easy if `h` is small, however becomes much more computationally demanding if `h` is large to simultaneously find `(h, P)\,|\,P\in E^\prime(\mathbb{F}_{p^2}), P\notin [r]E^\prime(\mathbb{F}_{p^2}), hP\in [r]E^\prime(\mathbb{F}_{p^2})`')

    print(f'For BN254, the factorization of the G2 cofactor are {factor(cofactor_E2)}, and since the "smallest" of these is 10069, small subgroup attacks are very difficult on BN254')
    
    return cofactor_E1, cofactor_E2
