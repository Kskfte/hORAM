import copy
import dpfLog
import random
import sys
from utils import byteXor,strXor
from Cryptodome.Random import get_random_bytes
def random_int_list(start, stop, length):
    start, stop = (int(start), int(stop)) if start <= stop else (int(stop), int(start))
    length = int(abs(length)) if length else 0
    random_list = []
    for _ in range(length):
        random_list.append(random.randint(start, stop))
    return random_list

def byteMul01(mul, b0):
    if mul==0:
        return byteXor(b0, b0)
    else:
        return b0

def strMul01(mul, s0):
    return str(mul*int(s0))

class PIRRead:
    """
    Storage form: (str, str, str)
    """
    def __init__(self, A0, A1, argNum) -> None:
        self.arrayLength = len(A0)
        self.A0 = A0 # copy.deepcopy(A)
        self.A1 = A1 # copy.deepcopy(A)
        self.argNum = argNum

    def read(self, x):
        dpf = dpfLog.logDPF(self.arrayLength)
        k_0, k_1 = dpf.gen_keys(x)
        if self.argNum==3:
            val_0 = (str(0),str(0),str(0))
            val_1 = (str(0),str(0),str(0))
            for i in range(self.arrayLength):
                bi0 = dpf.eval(0, k_0, i)
                bi1 = dpf.eval(1, k_1, i)
                val_0 = (strXor(val_0[0],strMul01(bi0,self.A0[i][0])),strXor(val_0[1],strMul01(bi0,self.A0[i][1])),strXor(val_0[2],strMul01(bi0,self.A0[i][2])))
                val_1 = (strXor(val_1[0],strMul01(bi1,self.A1[i][0])),strXor(val_1[1],strMul01(bi1,self.A1[i][1])),strXor(val_1[2],strMul01(bi1,self.A1[i][2])))
            return (strXor(val_0[0],val_1[0]),strXor(val_0[1],val_1[1]),strXor(val_0[2],val_1[2]))
        else:
            val_0 = (str(0),str(0))
            val_1 = (str(0),str(0))
            for i in range(self.arrayLength):
                bi0 = dpf.eval(0, k_0, i)
                bi1 = dpf.eval(1, k_1, i)
                assert ((i!=x) and (bi0^bi1==0)) or ((i==x) and (bi0^bi1==1))
                #print(strMul01(bi0,self.A0[i][0]))
                #print(strMul01(bi1,self.A1[i][0]))
                assert i==x or (strXor(strMul01(bi0,self.A0[i][0]), strMul01(bi1,self.A1[i][0]))=="0")
                val_0 = (strXor(val_0[0],strMul01(bi0,self.A0[i][0])),strXor(val_0[1],strMul01(bi0,self.A0[i][1])))
                val_1 = (strXor(val_1[0],strMul01(bi1,self.A1[i][0])),strXor(val_1[1],strMul01(bi1,self.A1[i][1])))
            # val_0 = val_0^(self.A0[i]*dpf.eval(0, k_0, i)) # Server 0 compute
            # val_1 = val_1^(self.A1[i]*dpf.eval(1, k_1, i)) # Server 1 compute
            return (strXor(val_0[0],val_1[0]),strXor(val_0[1],val_1[1]))
    
class PIRWrite:
    """
    storage form: (16-byte, str)
    """
    def __init__(self, A0, A1, argNum) -> None:
        self.arrayLength = len(A0)
        self.A0 = A0 #random_int_list(0, sys.maxsize, len(A))
        self.A1 = A1 #[self.A0[i]^A[i] for i in range(len(A))]
        self.argNum = argNum
    
    def write(self, x, oldV, newV):
        if self.argNum == 2:
            modV = (byteXor(oldV[0],newV[0]),strXor(oldV[1],newV[1]))
            dpf = dpfLog.logDPF(self.arrayLength)
            k_0, k_1 = dpf.gen_keys(x)
            for i in range(self.arrayLength):
                bi0 = dpf.eval(0, k_0, i) 
                bi1 = dpf.eval(1, k_1, i) 
                self.A0[i] = (byteXor(self.A0[i][0],byteMul01(bi0, modV[0])), strXor(self.A0[i][1],strMul01(bi0, modV[1])))
                self.A1[i] = (byteXor(self.A1[i][0],byteMul01(bi1, modV[0])), strXor(self.A1[i][1],strMul01(bi1, modV[1])))            
        else:
            modV = byteXor(oldV,newV)
            dpf = dpfLog.logDPF(self.arrayLength)
            k_0, k_1 = dpf.gen_keys(x)
            for i in range(self.arrayLength):
                bi0 = dpf.eval(0, k_0, i) 
                bi1 = dpf.eval(1, k_1, i)
                self.A0[i] = byteXor(self.A0[i],byteMul01(bi0, modV))
                self.A1[i] = byteXor(self.A1[i],byteMul01(bi1, modV))
                              
            #self.A0[i]^(modV*dpf.eval(0, k_0, i)) # Server 0 compute
            #self.A1[i] = self.A1[i]^(modV*dpf.eval(1, k_1, i)) # Server 1 compute
    
    def build(self):
        if self.argNum == 2:
            return [(byteXor(self.A0[i][0],self.A1[i][0]),strXor(self.A0[i][1],self.A1[i][1])) for i in range(len(self.A0))]
        else:
            return [byteXor(self.A0[i],self.A1[i]) for i in range(len(self.A0))]

if __name__=="__main__":


    RA0 = [('-1', '-1'), ('3', '6'), ('1', '4'), ('4', '7'), ('49', '52'), ('-1', '-1'), ('2', '5'), ('-1', '-1'), ('24', '27'), ('16', '19'), ('28', '31'), ('-1', '-1'), ('-1', '-1'), ('8', '11'), ('36', '39'), ('62', '65'), ('-1', '-1'), ('-1', '-1'), ('-1', '-1'), ('-1', '-1'), ('-1', '-1'), ('-1', '-1'), ('63', '66'), ('61', '64'), ('11', '14'), ('-1', '-1'), ('43', '46'), ('-1', '-1'), ('22', '25'), ('-1', '-1'), ('58', '61'), ('23', '26'), ('19', '22'), ('-1', '-1'), ('56', '59'), ('6', '9'), ('9', '12'), ('-1', '-1'), ('27', '30'), ('18', '21'), ('0', '3'), ('10', '13'), ('-1', '-1'), ('-1', '-1'), ('14', '17'), ('39', '42'), ('12', '15'), ('26', '29'), ('59', '62'), ('33', '36'), ('13', '16'), ('46', '49'), ('42', '45'), ('-1', '-1'), ('-1', '-1'), ('7', '10'), ('-1', '-1'), ('-1', '-1'), ('-1', '-1'), ('-1', '-1'), ('32', '35'), ('20', '23'), ('25', '28'), ('48', '51')] 
    RA1 = [('-1', '-1'), ('3', '6'), ('1', '4'), ('40', '43'), ('17', '20'), ('-1', '-1'), ('2', '5'), ('-1', '-1'), ('24', '27'), ('16', '19'), ('28', '31'), ('-1', '-1'), ('-1', '-1'), ('8', '11'), ('36', '39'), ('41', '44'), ('-1', '-1'), ('-1', '-1'), ('-1', '-1'), ('-1', '-1'), ('-1', '-1'), ('-1', '-1'), ('63', '66'), ('61', '64'), ('11', '14'), ('-1', '-1'), ('30', '33'), ('-1', '-1'), ('22', '25'), ('-1', '-1'), ('58', '61'), ('23', '26'), ('19', '22'), ('-1', '-1'), ('56', '59'), ('6', '9'), ('9', '12'), ('-1', '-1'), ('27', '30'), ('18', '21'), ('0', '3'), ('10', '13'), ('-1', '-1'), ('-1', '-1'), ('37', '40'), ('39', '42'), ('12', '15'), ('26', '29'), ('59', '62'), ('33', '36'), ('13', '16'), ('46', '49'), ('42', '45'), ('-1', '-1'), ('-1', '-1'), ('7', '10'), ('-1', '-1'), ('-1', '-1'), ('-1', '-1'), ('-1', '-1'), ('32', '35'), ('20', '23'), ('25', '28'), ('48', '51')] 
    #print(RA)
    ele = PIRRead(RA0,RA1,2).read(40)
    print(RA0[40])
    print(ele)
    #print(pirRead.read(1))
    #print(pirRead.read(2))
    #print(pirRead.read(3))
    #pirRead = PIRRead(A,A)
    #print(pirRead.read(1))

    """
    WA0 = [(get_random_bytes(16),str(random.randint(5,100))),(get_random_bytes(16),str(random.randint(5,100))),(get_random_bytes(16),str(random.randint(5,100))),(get_random_bytes(16),str(random.randint(5,100)))]
    WA1 = [(get_random_bytes(16),str(random.randint(5,100))),(get_random_bytes(16),str(random.randint(5,100))),(get_random_bytes(16),str(random.randint(5,100))),(get_random_bytes(16),str(random.randint(5,100)))]

    A = []
    for i in range(len(WA0)):
        A.append((byteXor(WA0[i][0],WA1[i][0]),strXor(WA0[i][1],WA1[i][1])))
    #WA0 = random_int_list(0, sys.maxsize, len(A))
    #WA1 = [A[i]^WA0[i] for i in range(len(A))]
    print(A)
    pirWrite = PIRWrite(WA0, WA1, 2)
    wr = get_random_bytes(16)
    print(wr)
    pirWrite.write(1, A[1], (wr, str(101)))
    print(pirWrite.build())


    WA0 = [(get_random_bytes(16),str(random.randint(5,100))),(get_random_bytes(16),str(random.randint(5,100))),(get_random_bytes(16),str(random.randint(5,100))),(get_random_bytes(16),str(random.randint(5,100)))]
    WA1 = [(get_random_bytes(16),str(random.randint(5,100))),(get_random_bytes(16),str(random.randint(5,100))),(get_random_bytes(16),str(random.randint(5,100))),(get_random_bytes(16),str(random.randint(5,100)))]

    A = []
    for i in range(len(WA0)):
        A.append((byteXor(WA0[i][0],WA1[i][0]),strXor(WA0[i][1],WA1[i][1])))
    #WA0 = random_int_list(0, sys.maxsize, len(A))
    #WA1 = [A[i]^WA0[i] for i in range(len(A))]
    print(A)
    pirWrite = PIRWrite(WA0, WA1, 2)
    wr = get_random_bytes(16)
    print(wr)
    pirWrite.write(1, A[1], (wr, str(101)))
    print(pirWrite.build())


    RA = [(str(random.randint(5,100)),str(random.randint(5,100)),str(random.randint(5,100))),(str(random.randint(5,100)),str(random.randint(5,100)),str(random.randint(5,100))),(str(random.randint(5,100)),str(random.randint(5,100)),str(random.randint(5,100))),(str(random.randint(5,100)),str(random.randint(5,100)),str(random.randint(5,100)))]
    print(RA)
    pirRead = PIRRead(RA,RA,2)
    print(pirRead.read(0))
    print(pirRead.read(1))
    print(pirRead.read(2))
    print(pirRead.read(3))
    #pirRead = PIRRead(A,A)
    #print(pirRead.read(1))

    """

