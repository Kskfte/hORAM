import math
tt = ["fss","fwr","twtw","yey","rwr","rwrw","w","p"]
for e in tt:
    print(hash(e+str(1))%2)
    print(hash(e+str(2))%2)
tList = [[0 for j in range(2**max(0,i-1))] for i in range(8+1)]
print(tList)
for j in range(0,8,2):
    print(j)
    print(j+1)