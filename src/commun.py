import sys
import os

def getArgv(name:str, default:str="") -> str:
	for i in range(len(sys.argv)-1):
		if sys.argv[i] == name:
			return sys.argv[i+1]
	return default

#load data file content
def dataLoad(file:str) -> str:
	res = ""
	if os.path.exists(file) == False:
		return res
	f = open(file, 'r')
	lines = f.readlines()
	f.close()
	for line in lines:
		val = line.strip('\n')
		val = val.strip('\r')
		res = res + val
	return res
