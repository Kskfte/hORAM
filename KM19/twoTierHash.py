import math
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

def computePosOfHash(secretKey, virAddr, bin_num_each_table):
    return hash(str(secretKey)+str(virAddr)) % bin_num_each_table

def computeRandomPos(bin_num_each_table):
    return random.randint(0,bin_num_each_table-1)

def computeCurrentTabSize(currentLevelEleNum, dbSize):
    """
    currentLevelEleNum is the element number before using the hash
    """
    epsilon = 0.75
    bin_num_each_table = math.ceil(currentLevelEleNum/math.pow(math.log2(dbSize),epsilon))
    size_each_bin = math.ceil(2*math.pow(math.log2(dbSize),epsilon))
    return bin_num_each_table,size_each_bin

class TwoTierHashMap:

    """
    element form
    """
    def __init__(self, levelCipher, dbSize, currentLevelEleNum, emptyElementForm) -> None:
        self.N = dbSize # Total No. of elements in ORAM, also be seen the security parameter lambda.    
        self.n = currentLevelEleNum # No. of elements for hashing
        self.epsilon = 0.75
        self.bin_num_each_table = math.ceil(self.n/math.pow(math.log2(self.N),self.epsilon))
        self.size_each_bin = math.ceil(2*math.pow(math.log2(self.N),self.epsilon))
        self.emptyElementForm = emptyElementForm

        self.table = ([[self.emptyElementForm for _ in range(self.size_each_bin)] for _ in range(self.bin_num_each_table)], [[self.emptyElementForm for _ in range(self.size_each_bin)] for _ in range(self.bin_num_each_table)])
        self.buffer = []
        self.hashfunction = (self.hash_one, self.hash_two)
        
        self.secretkey0 = levelCipher.encrypt(self.add_to_16(str(0)))
        self.secretkey1 = levelCipher.encrypt(self.add_to_16(str(1)))
        self.flag = True

    def add_to_16(self, value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)  # 返回bytes
    
    def hash_one(self, virAddr):
        return hash(str(self.secretkey0)+str(virAddr)) % (len(self.table[0]))

    def hash_two(self, virAddr):
        return hash(str(self.secretkey1)+str(virAddr)) % (len(self.table[1]))
    
    def insertEle(self, dataOrBlockArr):
        tempBuf = []
        for i in range(len(dataOrBlockArr)):
            virAddr, rValue = dataOrBlockArr[i]
            loc = self.hash_one(virAddr)
            if self.emptyElementForm in self.table[0][loc]:
                self.table[0][loc][self.table[0][loc].index(self.emptyElementForm)] = (virAddr, rValue)
            else:
                tempBuf.append((virAddr, rValue))
        
        for i in range(len(tempBuf)):
            virAddr, rValue = tempBuf[i]
            loc = self.hash_two(virAddr)
            if self.emptyElementForm in self.table[1][loc]:
                self.table[1][loc][self.table[1][loc].index(self.emptyElementForm)] = (virAddr, rValue)
            else:
                self.buffer.append((virAddr, rValue))

    def lookupWithSecretkey(self, virAddr):
        return (self.table[0][hash(str(self.secretkey0)+str(virAddr)) % (len(self.table[0]))], self.table[1][hash(str(self.secretkey1)+str(virAddr)) % (len(self.table[1]))])

    def lookup(self, LevelCipher, virAddr):
        secretkey0 = LevelCipher.encrypt(self.add_to_16(str(0)))#get_random_bytes(16)
        secretkey1 = LevelCipher.encrypt(self.add_to_16(str(1)))#get_random_bytes(16)
        return (self.table[0][hash(str(secretkey0)+str(virAddr)) % (len(self.table[0]))], self.table[1][hash(str(secretkey1)+str(virAddr)) % (len(self.table[1]))])
    
if __name__=="__main__":

    maxLevelKey = get_random_bytes(16)
    maxLevelCipher = AES.new(maxLevelKey, AES.MODE_ECB, use_aesni=True)
    A = []
    tagL = []
    emptyElementForm = ("-1","-1")
    PosOne = []
    PosTwo = []
    n = 2**6
    N = 2**12
    for i in range(n):
        A.append((str(i), str(i)))
    twoTierTab = TwoTierHashMap(maxLevelCipher, N, n, emptyElementForm)
    twoTierTab.insertEle(A)
    #print(twoTierTab.table[1])
    for i in range(n):
        t1, t2 = twoTierTab.lookupWithSecretkey(A[i][0])
        assert A[i] in t1 or A[i] in t2
 
    #print(PosTwo)

    