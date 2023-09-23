import math
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import sys
"""
A Cuckoo map contains two hash tables with each size (1+epsilon)*n and a stash with maximum size O(log n);
Thus, a cuckoo map consumes the storage with (1+epsilon)*2n + log n. Each lookup consumes bandwith with 2+log n;
We set the maximum eviction equals to alpha*log(n), the overflow probability less than n^(-O(log n)) for sufficiently large alpha.
We set alpha = log2(n), epsilon = 0.001
"""
class CuckooMap:

    """
    Store element form: (str, str, str) or (16-byte, str)
    """
    def __init__(self, levelCipher, alpha, epsilon, n, emptyEleForm) -> None:
        self.n = n
        self.alpha = alpha
        self.epsilon = epsilon #self.threshold_stash_size = math.ceil(math.log2(n))#10*math.ceil(math.log2(n))
        self.threshold_evict = self.alpha*math.ceil(math.log2(n))
        self.emptyEleForm = emptyEleForm	
        self.table = ([self.emptyEleForm for i in range((int)((1+self.epsilon)*n))], [self.emptyEleForm for j in range((int)((1+self.epsilon)*n))])
        
        """
        if self.emptyEleForm==("-1","-1"):
            self.table[0][0] = (str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))
            self.table[1][0] = (str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))
        elif self.emptyEleForm==bytes(16):
            self.table[0][0] = bytes(16)#get_random_bytes(16)
            self.table[1][0] = bytes(16)#get_random_bytes(16)
        elif self.emptyEleForm==("-1","-1","-1"):
            self.table[0][0] = (str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))
            self.table[1][0] = (str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))
        else: 
            self.table[0][0] = (bytes(16),"-1")#(get_random_bytes(16),str(random.randint(0,sys.maxsize)))
            self.table[1][0] = (bytes(16),"-1")#(get_random_bytes(16),str(random.randint(0,sys.maxsize)))
        
        """
        
        

        self.stash = []
        self.hashfunction = (self.hash_one, self.hash_two)
        
        self.secretkey0 = levelCipher.encrypt(self.add_to_16(str(0)))#get_random_bytes(16)
        self.secretkey1 = levelCipher.encrypt(self.add_to_16(str(1)))#get_random_bytes(16)
        self.flag = True

        self.dict = [{},{}]

    def add_to_16(self, value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)  # 返回bytes
    
    def hash_one(self, tag):
        """
        Ensure the position 0 does not store elements
        """
        return hash(str(self.secretkey0)+str(tag)) % (len(self.table[0])-1) + 1

    def hash_two(self, tag):
        return hash(str(self.secretkey1)+str(tag)) % (len(self.table[1])-1) + 1
    
    def hashWithS(self, secretKey, key):
        return hash(str(secretKey)+str(key)) % (len(self.table[0])-1) + 1
    
    def insertAllEle(self, tagList, preservedAList):
        for i in range(len(preservedAList)):
            self.insertOneEle(tagList[i], preservedAList[i])

        """
        for i in range(len(self.table[0])):
            if self.table[0][i] == self.emptyEleForm:
                if self.emptyEleForm==("-1","-1"):
                    self.table[0][i] = (str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))
                elif self.emptyEleForm==bytes(16):
                    self.table[0][i] = bytes(16)#get_random_bytes(16)
                elif self.emptyEleForm==("-1","-1","-1"):
                    self.table[0][i] = (str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))
                else:
                    self.table[0][i] = (bytes(16),"-1")#(get_random_bytes(16),str(random.randint(0,sys.maxsize)))
            
            if self.table[1][i] == self.emptyEleForm:
                if self.emptyEleForm==("-1","-1"):
                    self.table[1][i] = (str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))
                elif self.emptyEleForm==bytes(16):
                    self.table[1][i] = bytes(16)#get_random_bytes(16)
                elif self.emptyEleForm==("-1","-1","-1"):
                    self.table[1][i] = (str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))
                else:
                    self.table[1][i] = (bytes(16),"-1")#(get_random_bytes(16),str(random.randint(0,sys.maxsize)))

        """
        
    def insertOneEle(self, tag, preservedV): #key is tag, value is the form of (k,v,levelIndex)
        comp_tag = tag
        ins_preservedV = preservedV
        ins_table_num = 0
        Loc = [self.hash_one(comp_tag), self.hash_two(comp_tag)]
        kicked_pos = -1
        write_pos = -1
        kicked_V = self.emptyEleForm
        if self.table[0][Loc[0]]==self.emptyEleForm:
            self.table[0][Loc[0]]=ins_preservedV
            self.dict[0][Loc[0]] = Loc[1]
            return
        elif self.table[1][Loc[1]]==self.emptyEleForm:
            self.table[1][Loc[1]]=ins_preservedV
            self.dict[1][Loc[1]] = Loc[0]
            return
        else:
            ins_table_num = 0
            kicked_V = self.table[ins_table_num][Loc[ins_table_num]]
            kicked_pos = Loc[ins_table_num]
            write_pos = self.dict[ins_table_num][Loc[ins_table_num]]

            self.table[ins_table_num][Loc[ins_table_num]] = preservedV
            self.dict[ins_table_num][Loc[ins_table_num]] = Loc[ins_table_num^1]

            ins_table_num = ins_table_num^1

        count = 0
        while count<self.threshold_evict-1:
            if self.table[ins_table_num][write_pos]==self.emptyEleForm:
                self.table[ins_table_num][write_pos]=kicked_V
                self.dict[ins_table_num][write_pos]=kicked_pos
                return
            else:
                temp_kicked_V = self.table[ins_table_num][write_pos]
                temp_kicked_pos = write_pos
                temp_write_pos = self.dict[ins_table_num][write_pos]

                self.table[ins_table_num][write_pos] = kicked_V
                self.dict[ins_table_num][write_pos] = kicked_pos

                kicked_V = temp_kicked_V
                kicked_pos = temp_kicked_pos
                write_pos = temp_write_pos

                ins_table_num = ins_table_num^1

                count += 1
        if count==self.threshold_evict-1:
            self.stash.append(kicked_V)

    #def lookupWithoutSecretkey(self, key):
    #    return (self.stash, self.table[0][self.hash_one(key)], self.table[1][self.hash_two(key)])

    def lookup(self, maxLevelCipher, key):
        secretkey0 = maxLevelCipher.encrypt(self.add_to_16(str(0)))#get_random_bytes(16)
        secretkey1 = maxLevelCipher.encrypt(self.add_to_16(str(1)))#get_random_bytes(16)
        return (self.stash, self.table[0][self.hashWithS(secretkey0, key)], self.table[1][self.hashWithS(secretkey1, key)])
    
    def getPos(self, maxLevelCipher, key):
        secretkey0 = maxLevelCipher.encrypt(self.add_to_16(str(0)))#get_random_bytes(16)
        secretkey1 = maxLevelCipher.encrypt(self.add_to_16(str(1)))#get_random_bytes(16)
        return self.hashWithS(secretkey0, key), self.hashWithS(secretkey1, key)

if __name__=="__main__":

    maxLevelKey = get_random_bytes(16)#b'\xae\xf6}\x00^\xd9\x0cE\x03 \xe5;\xac\xf8L\xfb'#random.randbytes(16)
    print(maxLevelKey)
    maxLevelCipher = AES.new(maxLevelKey, AES.MODE_ECB, use_aesni=True)

    A = []
    tagL = []

    PosOne = []
    PosTwo = []
    
    n = 2**10
    ht = CuckooMap(maxLevelCipher, math.ceil(math.log2(n)), 0.001, n, ("-1","-1"))

    #key = maxLevelCipher.encrypt(ht.add_to_16(str(1)+str(2)))
    #mm = AES.new(key, AES.MODE_ECB, use_aesni=True)
    #print(mm.encrypt(ht.add_to_16(str(1)+str(2))))
    #key2 = maxLevelCipher.encrypt(ht.add_to_16(str(1)+str(2)))
    #mm2 = AES.new(key2, AES.MODE_ECB, use_aesni=True)
    #print(mm2.encrypt(ht.add_to_16(str(1)+str(2))))

    #print(ht.table[0])
    #print(ht.table[1])
    for i in range(n):
        A.append((maxLevelCipher.encrypt(ht.add_to_16(str(i)))[:16], str(i)))
        
        #secretkey1 = maxLevelCipher.encrypt(ht.add_to_16(str(0)))#get_random_bytes(16)
        #secretkey2 = maxLevelCipher.encrypt(ht.add_to_16(str(1)))#get_random_bytes(16)
        #cipher1 = AES.new(secretkey1, AES.MODE_ECB, use_aesni=True)
        #cipher2 = AES.new(secretkey2, AES.MODE_ECB, use_aesni=True)
        #PosOne.append(int.from_bytes(cipher1.encrypt(ht.add_to_16(str(str(i)))), 'big', signed=False)%len(ht.table[0]))
        #PosTwo.append(int.from_bytes(cipher2.encrypt(ht.add_to_16(str(str(i)))), 'big', signed=False)%len(ht.table[0]))
        tagL.append(maxLevelCipher.encrypt(ht.add_to_16(str(i)))[:16]) #int.from_bytes(maxLevelCipher.encrypt(self.add_to_16(str(i+2))), 'big', signed=False)
    
    ht.insertAllEle(tagL, A)
    ht2 = CuckooMap(maxLevelCipher, math.ceil(math.log2(n)), 0.001, n, ("-1","-1"))
    ht2.insertAllEle(tagL, A)
    for i in range(len(ht.table[0])):
        assert ht.table[0][i]==ht2.table[0][i]
    print(len(ht.stash))

    for i in range(10):
        s, t1, t2 = ht.lookup(maxLevelCipher, tagL[i])
        assert t1==A[i] or t2==A[i] or A[i] in s
        assert len(tagL[i])==16
    print(ht.stash)
    print(len(ht.table[0]))
    print(len(ht.stash))
    #print(PosTwo)

    