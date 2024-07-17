f = open("bn254_reference.json", "r")
lines = f.read()
testData = json.loads(lines)
testDataTwo = {'private_keys': testData['private_keys']}
for field in list(testData.keys()):
	simplifiedField = []
	print(field)
	if field == 'private_keys':
		continue
	elif field == 'G1_signatures' or field == 'svdw':
		for entry in testData[field]:
			simplifiedField.append([int(value) for value in list(entry.values())])
	else:
		for entry in testData[field]:
			objPair = []
			for obj in list(entry.values()):
				objPair.append([int(value) for value in list(obj.values())])
			simplifiedField.append(objPair)
	testDataTwo[field] = simplifiedFiel
print(testDataTwo)
