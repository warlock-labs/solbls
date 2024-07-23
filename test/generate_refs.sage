from sagelib.utils import *
from sagelib.svdw import generic_svdw
from sagelib.small_subgroup import attack_risk

# Generate random points
num_points = 1000
points = {
    "G1_signatures": [],
    "G2_public_keys": [],
    "E2_non_G2": [],
    "private_keys": [],
    "svdw": []
}

for _ in range(num_points):
    # Generate keypair and signature
    private_key, public_key = generate_keypair()
    signature = sign(private_key)
    points["private_keys"].append(private_key)
    points["G1_signatures"].append(point_to_json(signature))
    points["G2_public_keys"].append(point_to_json(public_key))

    # E2 point not in G2
    P_non_G2 = generate_non_r_torsion_point()
    points["E2_non_G2"].append(point_to_json(P_non_G2))
 
cofactor_g1, cofactor_g2 = attack_risk(E1, E2, r)

###
# now we generate the SVDW vectors for the comparison with the solidity implementation

svdw = generic_svdw(E1)
for _ in range(num_points):
    u = Fp.random_element()
    if u not in svdw.undefs:
        x, y = svdw.map_to_point(u)
        assert E1(x,y), f"point ({x},{y}) is not on the curve for u = {u}"
        points["svdw"].append({
            "i" : str(u),
            **point_to_json(E1(x,y))})
# import json
# with open('bn254_reference.json', 'w') as f:
#    f.write(json.dumps(points,indent=2))

pointsTwo = {'private_keys': points['private_keys']}
for field in list(points.keys()):
	simplifiedField = []
	print(field)
	if field == 'private_keys':
		continue
	elif field == 'G1_signatures' or field == 'svdw':
		for entry in points[field]:
			simplifiedField.append([int(value) for value in list(entry.values())])
	else:
		for entry in points[field]:
			objPair = []
			for obj in list(entry.values()):
				for value in list(obj.values()):
					objPair.append(int(value))
			simplifiedField.append(objPair)
	pointsTwo[field] = simplifiedField
with open('bn254_reference_transformed.json', 'w') as f:
	f.write(json.dumps(pointsTwo,indent=2))
