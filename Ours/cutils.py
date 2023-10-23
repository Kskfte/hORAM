import math
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import time
import copy
import hashlib


def add_to_16(value):
    while len(value) % 16 != 0:
        value += "\0"#str(random.randint(0, sys.maxsize))
    return str.encode(value)  # 返回bytes 

def convert(convertKey, s):
    #convertCipher = AES.new(convertKey, AES.MODE_ECB, use_aesni=True)
    
    sha1 = hashlib.sha1()
    sha1.update(add_to_16(str(convertKey)+str(s)))
    return int.from_bytes(sha1.digest(), 'big', signed=False)%2#int.from_bytes(convertCipher.encrypt(add_to_16(str(s)+str(-1))), 'big', signed=False)%2 #int.from_bytes(convertCipher.encrypt(add_to_16(str(s)+str(-1))), 'big', signed=False)

def prg(secretKey, s):
    """
    lambda -> 2*lambda +2 
    Assume s is 16-byte
    """
    secretCipher = AES.new(secretKey, AES.MODE_ECB, use_aesni=True)
    sL = secretCipher.encrypt(add_to_16(str(0)+str(s)))[:16]
    sR = secretCipher.encrypt(add_to_16(str(1)+str(s)))[:16]
    #sha1 = hashlib.sha1()
    sha1 = hashlib.sha1()
    sha1.update(add_to_16(str(2)+str(secretKey)+str(s)))
    tL = int.from_bytes(sha1.digest(), 'big', signed=False)%2#int.from_bytes(secretCipher.encrypt(add_to_16(str(s)+str(2))), 'big', signed=False)%2
    
    sha1 = hashlib.sha1()
    sha1.update(add_to_16(str(3)+str(secretKey)+str(s)))
    tR = int.from_bytes(sha1.digest(), 'big', signed=False)%2#int.from_bytes(secretCipher.encrypt(add_to_16(str(s)+str(3))), 'big', signed=False)%2
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

def strXor(s1, s2):
    return str(int(s1)^int(s2))

def bytesToStr(mb):
    return str(int.from_bytes(mb, 'big', signed=False))

def strToBytes(str):
    return int.to_bytes(int(str), 16, 'big', signed=False)

def packToStr(eleAndT):
    """
    Only for table ele and table tag
    """
    res = ""
    for e in eleAndT:
        if isinstance(e, bytes):
            res = res + bytesToStr(e) + " "
        else:
            res = res + str(e) + " "
    return res

def pirWriteVToStrEll(modV):
    if len(modV)==2:
        return bytesToStr(modV[0])+" "+modV[1]+" "
    else:
        return bytesToStr(modV)+" "
    
def dpfKeysToStr(dpfK):
    prgK, convertK, (sk, CW) = dpfK
    res = bytesToStr(prgK) + " " + bytesToStr(convertK) + " " + bytesToStr(sk) + " "
    for i in range(1, len(CW)-1):
        s_CW, tL_CW, tR_CW = CW[i]
        res = res + bytesToStr(s_CW)+" "+str(tL_CW)+" "+ str(tR_CW)+" "
    res = res + str(CW[len(CW)-1])+" "
    return res

def modVAndDpfKeysToStr(modV, dpfK):
    res = str(len(modV))+" "
    res += pirWriteVToStrEll(modV)
    res += dpfKeysToStr(dpfK)
    return res

def strToDpfKeys(res):
    sp = res.split( )
    prgK = strToBytes(sp[0])
    convertK = strToBytes(sp[1])
    sk = strToBytes(sp[2])
    CW = []
    for i in range(3, len(sp)-1, 3):
        CW.append((strToBytes(sp[i]),int(sp[i+1]),int(sp[i+2])))
    CW.append(int(sp[len(sp)-1]))
    #print((prgK, convertK, (sk, CW)))
    return prgK, convertK, (sk, CW)

def pirstrToVEll(str):
    tml = str.split( )
    if len(tml)==2:
        return (strToBytes(tml[0]), tml[1])
    else:
        return strToBytes(tml[0])

def arrayToDpfKeys(sp):
    prgK = strToBytes(sp[0])
    convertK = strToBytes(sp[1])
    sk = strToBytes(sp[2])
    CW = []
    for i in range(3, len(sp)-1, 3):
        CW.append((strToBytes(sp[i]),int(sp[i+1]),int(sp[i+2])))
    CW.append(int(sp[len(sp)-1]))
    return prgK, convertK, (sk, CW)

def arrayToModV(tml):
    if len(tml)==2:
        return (strToBytes(tml[0]), tml[1])
    else:
        return strToBytes(tml[0])
    
def strToModVAndDpfKeys(str):
    res = str.split( )
    lenModV = int(res[0])
    modV = arrayToModV(res[1:1+lenModV])
    prgK, convertK, (sk, CW) = arrayToDpfKeys(res[1+lenModV:])
    return modV, (prgK, convertK, (sk, CW))

def byteMul01(mul, b0):
    if mul==0:
        return byteXor(b0, b0)
    else:
        return b0

def strMul01(mul, s0):
    return str(mul*int(s0))   

def pirWriteWithEval(argNum, Bi, modV, A):
    if argNum == 2:
        for i in range(1, len(A)): #1, self.arrayLength
            bi = Bi[i]
            A[i] = (byteXor(A[i][0],byteMul01(bi, modV[0])), strXor(A[i][1],strMul01(bi, modV[1])))          
    else:
        for i in range(1, len(A)):
            bi = Bi[i]
            A[i] = byteXor(A[i],byteMul01(bi, modV))
                            
def pirWriteWithEvalAndPos(argNum, Bi, modV, A, dictKV):
    if argNum == 2:
        for i in dict.keys(dictKV):
            bi = Bi[i]
            A[i] = (byteXor(A[i][0],byteMul01(bi, modV[0])), strXor(A[i][1],strMul01(bi, modV[1])))          
    else:
        for i in dict.keys(dictKV):
            bi = Bi[i]
            A[i] = byteXor(A[i],byteMul01(bi, modV))

def readWithPos(argNum, Bi, A, dictKV):
    if argNum==3:
        val_0 = (str(0),str(0),str(0))
        for i in dict.keys(dictKV):
            bi = Bi[i]
            val_0 = (strXor(val_0[0],strMul01(bi,A[i][0])),strXor(val_0[1],strMul01(bi,A[i][1])),strXor(val_0[2],strMul01(bi,A[i][2])))
        return val_0
    else:
        val_0 = (str(0),str(0))
        for i in dict.keys(dictKV):
            bi = Bi[i]
            val_0 = (strXor(val_0[0],strMul01(bi,A[i][0])),strXor(val_0[1],strMul01(bi,A[i][1])))
        return val_0


def dpfGenKeys(index, arrayLength):
    """
    f(alpha, beta)
    we set beta=1
    """
    n = math.ceil(math.log2(arrayLength))
    prgKey = get_random_bytes(16)
    convertKey = get_random_bytes(16)
    L = 0
    R = 1

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
        sL_0,tL_0,sR_0,tR_0 = prg(prgKey, s_0List[i-1])
        sL_1,tL_1,sR_1,tR_1 = prg(prgKey, s_1List[i-1])
        Keep = L^Alpha[i]
        Lose = R^Alpha[i]
        s_CW = ""
        if Lose==0:
            s_CW = byteXor(sL_0,sL_1)
        else:
            s_CW = byteXor(sR_0,sR_1)
        tL_CW = tL_0^tL_1^Alpha[i]^1
        tR_CW = tR_0^tR_1^Alpha[i]
        CW[i] = s_CW, tL_CW, tR_CW
        if Keep==0:
            s_0List[i] = byteXor(sL_0,byteMul01(t_0List[i-1],s_CW))
            s_1List[i] = byteXor(sL_1,byteMul01(t_1List[i-1],s_CW))
            t_0List[i] = tL_0^(t_0List[i-1]*tL_CW)
            t_1List[i] = tL_1^(t_1List[i-1]*tL_CW)
        else:
            s_0List[i] = byteXor(sR_0,byteMul01(t_0List[i-1],s_CW))
            s_1List[i] = byteXor(sR_1,byteMul01(t_1List[i-1],s_CW))
            t_0List[i] = tR_0^(t_0List[i-1]*tR_CW)
            t_1List[i] = tR_1^(t_1List[i-1]*tR_CW)
        
    CW[n+1] = ((-1)**t_1List[n])*(1-convert(convertKey, s_0List[n])+convert(convertKey, s_1List[n]))%2
    k_0 = s_0List[0],CW
    k_1 = s_1List[0],CW
    return prgKey, convertKey, k_0, k_1

def dpfEvalAll(prgKey, convertKey, arrayLength, b, k_b):
    n = math.ceil(math.log2(arrayLength))
    resList = []
    #[[0 for j in range(2**i)] for i in range(8+1)]
    sList = [["" for j in range(2**i)] for i in range(n+1)]
    tList = [[0 for j in range(2**i)] for i in range(n+1)]
    

    sList[0][0], CW = k_b#copy.deepcopy(k_b)#k_b#
    #print(n)
    #print(CW)
    #print(k_b)
    #print(CW)
    tList[0][0] = b
    for i in range(1, n+1):
        for j in range(0, 2**i, 2):
            #(s_CW, tL_CW, tR_CW) = CW[i]
            tempsL, temptL, tempsR, temptR = prg(prgKey, sList[i-1][j//2])
            sList[i][j] = byteXor(tempsL,byteMul01(tList[i-1][j//2],CW[i-1][0]))
            tList[i][j] = temptL^(tList[i-1][j//2]*CW[i-1][1])
            sList[i][j+1] = byteXor(tempsR,byteMul01(tList[i-1][j//2],CW[i-1][0]))
            tList[i][j+1] = temptR^(tList[i-1][j//2]*CW[i-1][2])
    #print(CW[n])
    #for i in CW:
    #    print(i)
    #print(len(CW))
    #print(CW[n])
    for i in range(2**n):
        resList.append(((-1)**b)*(convert(convertKey, sList[n][i])+tList[n][i]*CW[n])%2)
    
    return resList

if __name__=="__main__":
    #print(hash("12"))
    #pk = b'\xb3\x14\xabgbBL+pN\x96\xea@\x93]{'
    #ck = b'\xe3+(&T8h:\xcb\xfd\xac\xd6<%\xd7\xc6'
    #k0 = (b'p\xfb\xb9\xd60D\x90FK-i\x86N\xc1\xe1\xfd', [(b'x\x82\xc4bs\xf3y\xf6\xbd$\xa1\\\xe3\xfc\x08\x9e', 1, 0), (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 1, 0), (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 0, 1), (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 1, 0), 1])
    #k1 = (b'\xe1\xb8(\x84\x97\x13\x15\xdc7\xeb&[\xac\xba\x8cY', [(b'x\x82\xc4bs\xf3y\xf6\xbd$\xa1\\\xe3\xfc\x08\x9e', 1, 0), (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 1, 0), (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 0, 1), (b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 1, 0), 1])
    arrL = 129
    ind = 127
    pk,ck,k0 = (b'\xb4\x0b\xef\xa0N\xbaF:f4\xba\r=\xb8a\x81', b'C\x80\xbc_I\xa6\xa6\xd2\n\xdb\xe3\xe0E"\xc7\x99', (b'\x03\xc9I{\xeb\x97\x93\xa2s!\x05\xf7P\xf5b\xa4', [(b'\x8ddy\xba\xf5\x88\xd8)\xae8,\xf0H\xa6\xd1\xe8', 0, 0), (b'=\x13\xd6oy\xe3\x1c)6Y,157\xf3\x98', 1, 0), (b'\x17Tr\xf3\xad\x9a\xd20t+\xfcH\xa6\xb7\xfaa', 0, 1), (b'\xdd\x0b#,\x17\x16q\xca\xab`\xe6\x80\xd5\xfc\x18\x0c', 0, 0), (b'1\xf0\xe6\xdf\xe4\xd6\xbf\xcb\x1a\xec\xf9\xf1H%\xf6\xb7', 0, 1), (b'\x02U=1\x08\xba\x19\xe0*\x89\n\x88\xd4\xcd\n\xdc', 1, 1), (b'\x81\x1b\x94\x8d\xbc\xd9\x9a\rh\x03\x18\x8a;\xdaz\x03', 0, 0), (b'\xa7\x94\xaf\x92\x88\xbb\xd7$\x16\xb7l\xbb#W3G', 1, 0), (b'\x1e<\x8b\x86\xba\xf73\xfa\n\xa1T\xfe\xbb\xfd\xc5\xc0', 1, 1), 1]))
    #pk = b'\xc3e\x0ej\x8b=,"x\xec\x00\xc2\xf4kb\xa0'
    #ck = b'\xe0\xf3\xf2\xef~\xc1Xpf\x06\x8au\x04\x8f\x18\x07'
    #k0 = (b'\x1d\xdb\x8f\xed9U|\xa1\xac\x06\xaf\xf8\xe7\xcd\xa2\x16', ['', (b'\xb3\x8f!?M8*\x979\x80\x7f\xd3\xee&x3', 0, 0), (b'^\x15|k\xd8~\x82\x0bGbdE\x96\x9eo\x07', 1, 1), (b'\x14@p#sW\xb0\x8c\x1f55\xb4$A\xbfN', 0, 0), (b'\xfc\x1b\xa4\xfb \x04\x81F\x13\xed@\x03/\xe9\xc6h', 0, 0), (b'\xc8\xa7\xd2\xfb\xde6z\xf2\x967\xac\xc6\x9flA\xbc', 0, 0), (b'k\xcf\x9d\xb4\xe3\x0b\xd7\x07c\xffB$[\x86\x83\xb4', 1, 0), (b'TQ\xa9\x86\x10\x13uB\xcd\x82\x0b&\xc2S\xd6p', 0, 1), (b'\x93C\xd0\t\x9frZi\xd7\xc4O\x8c8n\xe7t', 0, 0), 0])
    #k1 = (b'z\xdes|`\xa0\xbd\xbe\xe5\x97\x10\x9d\xa2p\xb5\xa7', ['', (b'\xb3\x8f!?M8*\x979\x80\x7f\xd3\xee&x3', 0, 0), (b'^\x15|k\xd8~\x82\x0bGbdE\x96\x9eo\x07', 1, 1), (b'\x14@p#sW\xb0\x8c\x1f55\xb4$A\xbfN', 0, 0), (b'\xfc\x1b\xa4\xfb \x04\x81F\x13\xed@\x03/\xe9\xc6h', 0, 0), (b'\xc8\xa7\xd2\xfb\xde6z\xf2\x967\xac\xc6\x9flA\xbc', 0, 0), (b'k\xcf\x9d\xb4\xe3\x0b\xd7\x07c\xffB$[\x86\x83\xb4', 1, 0), (b'TQ\xa9\x86\x10\x13uB\xcd\x82\x0b&\xc2S\xd6p', 0, 1), (b'\x93C\xd0\t\x9frZi\xd7\xc4O\x8c8n\xe7t', 0, 0), 0])

    res = dpfEvalAll(pk,ck,(int)((1+0.01)*(2**8)),0,k0)#(k0[0],k0[1][1:])
    print(res)

    #res2 = dpfEvalAll(pk,ck,arrL,1,(k1[0],k1[1][1:]))#(k1[0],k1[1][1:])
    #print(res2)
    for i in range(len(res)):
        print(i)
        #assert i!=ind and res[i]==res2[i] or i==ind and res[i]!=res2[i]
    #print(k0)
    #print(k1)
    #sha1 = hashlib.sha1()
    #sha1.update(pk)
    #sha1.
    #print(sha1.digest())
    #print(k1[0])
    #print(k1[1][1:])
    #A0 = [get_random_bytes(16),get_random_bytes(16)]
    #A1 = [get_random_bytes(16),get_random_bytes(16)]
    #print(A0)
    #print(A1)

    """
    Arr = [('-1', '-1'), ('4', '6'), ('2', '4'), ('-1', '-1'), ('5', '7'), ('-1', '-1'), ('8', '10'), ('15', '17'), ('6', '8'), ('-1', '-1'), ('1', '3'), ('-1', '-1'), ('16', '18'), ('-1', '-1'), ('-1', '-1'), ('-1', '-1')]
    levelSecretkey = get_random_bytes(16)
    levelCipher = AES.new(levelSecretkey, AES.MODE_ECB, use_aesni=True)
    cuc = CuckooMap(levelCipher,math.ceil(math.log2(len(Arr))),0.01,len(Arr),('-1','-1'))
    tagL = []
    for i in range(len(Arr)):
        tagL.append(get_random_bytes(16))
    cuc.insertAllEle(tagL,Arr)
    print(cuc.table[0])
    print(cuc.table[1])
    print(cuc.dict[0])
    print(cuc.dict[1])
    #dictKV = {}
    #for e in Arr:
    #    dictKV[e[0]]=e[1]
    tagSecretkey = get_random_bytes(16)
    tagCipher = AES.new(tagSecretkey, AES.MODE_ECB, use_aesni=True)
    prgk, ck, k0, k1 = dpfGenKeys(6,len(cuc.table[0]))
    (s0, CW) = k0
    (s1, CW) = k1
    print(CW)
    CW = CW[1:]
    print(CW)
    k0 = (s0,CW)
    k1 = (s1,CW)
    Bi0 = dpfEvalAll(prgk, ck, len(cuc.table[0]), 0, k0)
    Bi1 = dpfEvalAll(prgk, ck, len(cuc.table[0]), 1, k1)
    print(Bi0)
    print(Bi1)
    val0 = readWithPos(2,Bi0,cuc.table[0],cuc.dict[0])
    val1 = readWithPos(2,Bi1,cuc.table[0],cuc.dict[0])
    print(strXor(val0[0],val1[0]),strXor(val0[1],val1[1])) 
    """

    
    #
    # ekfk = (bytes(16),"13","52")
    #print(packToStr(ekfk).split( ))
    