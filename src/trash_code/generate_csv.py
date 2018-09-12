#!/usr/bin/env python

import os,sys
import numpy as np
import csv 
input="csv_results_4"
output="IoT_CSVs"

#arr=[[0,2],[3,0],[5,0]]

for item in sorted(os.listdir(input)):
	if os.path.isdir(input+"\\"+item):
		with open(output+"\\"+item+".csv","wb") as c:
			wr = csv.writer(c)
			for f in os.listdir(input+"\\"+item):
				x = np.genfromtxt(input+"\\"+item+"\\"+f, delimiter='\t',usecols = range(0,23))
				if x.shape[0]%12 ==0:
					for i in range(0,x.shape[0]/12):
						arr=x[i*12:(i+1)*12,:].tolist()
						flatten = [j for k in arr for j in k]
						wr.writerow(flatten)
				else:
					for i in range(0,int(x.shape[0]/12)+1):
						arr=x[i*12:(i+1)*12,:].tolist()
						flatten = [j for k in arr for j in k]
						if i==int(x.shape[0]/12):
							pad = [0] * (276-len(flatten))
							flatten.extend(pad)
						wr.writerow(flatten)
				#sys.exit(1)
