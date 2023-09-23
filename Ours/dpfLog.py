import random
import math
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import time
import sys
"""
Linear PIR read
type(key) = str
type(value) = int
"""
def add_to_16(value):
    while len(value) % 16 != 0:
        value += "\0"#str(random.randint(0, sys.maxsize))
    return str.encode(value)  # 返回bytes 

def convert(convertKey, s):
    convertCipher = AES.new(convertKey, AES.MODE_ECB, use_aesni=True)
    return hash(str(convertKey)+str(s))%2 #int.from_bytes(convertCipher.encrypt(add_to_16(str(s)+str(-1))), 'big', signed=False)

def prg(secretKey, s):
    """
    lambda -> 2*lambda +2 
    Assume s is 16-byte
    """
    secretCipher = AES.new(secretKey, AES.MODE_ECB, use_aesni=True)
    sL = secretCipher.encrypt(add_to_16(str(s)+str(0)))[:16]
    sR = secretCipher.encrypt(add_to_16(str(s)+str(1)))[:16]
    tL = hash(str(secretKey)+str(s)+str(2))%2#int.from_bytes(secretCipher.encrypt(add_to_16(str(s)+str(2))), 'big', signed=False)%2
    tR = hash(str(secretKey)+str(s)+str(3))%2#int.from_bytes(secretCipher.encrypt(add_to_16(str(s)+str(3))), 'big', signed=False)%2
    return sL,tL,sR,tR

def bitExtract(ind, n):
    res = [0 for i in range(n+1)]
    for i in range(n):
        res[i+1] = ind>>(n-i-1)&1
    return res

def byteXor(b1, b2):
    result = bytearray(b1)
    for i, b in enumerate(b2):
        result[i] ^= b
    return bytes(result)
    
class logDPF:

    def __init__(self, input_length):
        """
        Ensure the input array length is the power of 2
        """
        self.input_length = 2**(math.ceil(math.log2(input_length)))
        self.prgKey = get_random_bytes(16)
        self.convertKey = get_random_bytes(16)
        self.L = 0
        self.R = 1
    
    def gen_keys(self, index):
        """
        f(alpha, beta)
        we set beta=1
        """
        n = math.ceil(math.log2(self.input_length))
        s_0List = ["" for i in range(n+1)]
        s_1List = ["" for i in range(n+1)] 
        t_0List = [0 for i in range(n+1)]
        t_1List = [0 for i in range(n+1)]

        s_0List[0] = get_random_bytes(16)
        s_1List[0] = get_random_bytes(16)
        t_0List[0] = 0
        t_1List[0] = 1
        CW = ["" for i in range(n+2)]
        Alpha = bitExtract(index, n)

        for i in range(1, n+1):
            sL_0,tL_0,sR_0,tR_0 = prg(self.prgKey, s_0List[i-1])
            sL_1,tL_1,sR_1,tR_1 = prg(self.prgKey, s_1List[i-1])
            Keep = self.L^Alpha[i]
            Lose = self.R^Alpha[i]
            s_CW = ""
            if Lose==0:
                s_CW = byteXor(sL_0,sL_1)
            else:
                s_CW = byteXor(sR_0,sR_1)
            tL_CW = tL_0^tL_1^Alpha[i]^1
            tR_CW = tR_0^tR_1^Alpha[i]
            CW[i] = s_CW, tL_CW, tR_CW
            if Keep==0:
                s_0List[i] = byteXor(sL_0,t_0List[i-1]*s_CW)
                s_1List[i] = byteXor(sL_1,t_1List[i-1]*s_CW)
                t_0List[i] = tL_0^(t_0List[i-1]*tL_CW)
                t_1List[i] = tL_1^(t_1List[i-1]*tL_CW)
            else:
                s_0List[i] = byteXor(sR_0,t_0List[i-1]*s_CW)
                s_1List[i] = byteXor(sR_1,t_1List[i-1]*s_CW)
                t_0List[i] = tR_0^(t_0List[i-1]*tR_CW)
                t_1List[i] = tR_1^(t_1List[i-1]*tR_CW)
            
        CW[n+1] = ((-1)**t_1List[n])*(1-convert(self.convertKey, s_0List[n])+convert(self.convertKey, s_1List[n]))%2
        k_0 = s_0List[0],CW
        k_1 = s_1List[0],CW
        return k_0, k_1
    
    def eval(self, b, k_b, x):
        n = math.ceil(math.log2(self.input_length))
        sList = ["" for i in range(n+1)]
        tList = [0 for i in range(n+1)]
        bitX = bitExtract(x, n)

        sList[0], CW = k_b
        tList[0] = b
        for i in range(1, n+1):
            s_CW, tL_CW, tR_CW = CW[i]
            tempsL, temptL, tempsR, temptR = prg(self.prgKey, sList[i-1])
            sL = byteXor(tempsL,tList[i-1]*s_CW)
            tL = temptL^(tList[i-1]*tL_CW)
            sR = byteXor(tempsR,tList[i-1]*s_CW)
            tR = temptR^(tList[i-1]*tR_CW)
            if bitX[i]==0:
                sList[i] = sL
                tList[i] = tL
            else:
                sList[i] = sR
                tList[i] = tR
        return ((-1)**b)*(convert(self.convertKey, sList[n])+tList[n]*CW[n+1])%2
    
    def evalAll(self, b, k_b):
        n = math.ceil(math.log2(self.input_length))
        resList = []
        #[[0 for j in range(2**i)] for i in range(8+1)]
        sList = [["" for j in range(2**i)] for i in range(n+1)]
        tList = [[0 for j in range(2**i)] for i in range(n+1)]

        sList[0][0], CW = k_b
        tList[0][0] = b
        for i in range(1, n+1):
            for j in range(0, 2**i, 2):
                s_CW, tL_CW, tR_CW = CW[i]
                tempsL, temptL, tempsR, temptR = prg(self.prgKey, sList[i-1][j//2])
                sList[i][j] = byteXor(tempsL,tList[i-1][j//2]*s_CW)
                tList[i][j] = temptL^(tList[i-1][j//2]*tL_CW)
                sList[i][j+1] = byteXor(tempsR,tList[i-1][j//2]*s_CW)
                tList[i][j+1] = temptR^(tList[i-1][j//2]*tR_CW)

        for i in range(2**n):
            resList.append(((-1)**b)*(convert(self.convertKey, sList[n][i])+tList[n][i]*CW[n+1])%2)
        
        return resList
        
if __name__=="__main__":
    input_length = 5
    dpf = logDPF(input_length)
    res1 = []
    res2 = []
    b1 = time.time()
    #for i in range(input_length):
    k_0, k_1 = dpf.gen_keys(2)
    for j in range(input_length):   
        val0 = dpf.eval(0, k_0, j)
        val1 = dpf.eval(1, k_1, j)
        res1.append(val0)
        res2.append(val1)
        #assert ((i!=j) and (val1^val0==0)) or ((i==j) and (val1^val0==1))
    print(res1)
    print(res2)

    e1 = time.time()

    res3 = []
    res4 = []
    b2 = time.time()
    k_0, k_1 = dpf.gen_keys(2)
    print(dpf.evalAll(0,k_0))
    print(dpf.evalAll(1,k_1))
    e2 = time.time()
    print(e1-b1)
    print(e2-b2)





