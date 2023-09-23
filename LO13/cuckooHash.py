import math
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
class CuckooMap:

    """
    A Cuckoo map contains two hash tables with each size (1+epsilon)*n and a stash with maximum size O(log n);
    Thus, a cuckoo map consumes the storage with (1+epsilon)*2n + log n. Each lookup consumes bandwith with 2+log n;
    We set the maximum eviction equals to alpha*log(n), the overflow probability less than n^(-O(log n)) for sufficiently large alpha.
    We set alpha = log2(n), epsilon = 0.01
    """
    """
    Table element form: (str, str, str): (level, levelEpoch, virtualAddress)
    """
    def __init__(self, levelCipher, alpha, epsilon, n) -> None:    
        self.n = n
        self.alpha = alpha
        self.epsilon = epsilon
        self.threshold_stash_size = math.ceil(math.log2(n))#10*math.ceil(math.log2(n))
        self.threshold_evict = self.alpha*math.ceil(math.log2(n))	
        self.table = ([("",("","")) for i in range((int)((1+self.epsilon)*n))], [("",("","")) for j in range((int)((1+self.epsilon)*n))])
        self.stash = []
        self.hashfunction = (self.hash_one, self.hash_two)
        
        self.secretkey0 = levelCipher.encrypt(self.add_to_16(str(0)))#get_random_bytes(16)
        self.secretkey1 = levelCipher.encrypt(self.add_to_16(str(1)))#get_random_bytes(16)
        #self.cipher1 = AES.new(self.secretkey1, AES.MODE_ECB, use_aesni=True)
        #self.cipher2 = AES.new(self.secretkey2, AES.MODE_ECB, use_aesni=True)
        #print(len(self.secretkey1))
        self.flag = True

    def add_to_16(self, value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)  # 返回bytes
    
    def hash_one(self, tag):
        return hash(str(self.secretkey0)+str(tag)) % (len(self.table[0]))

    def hash_two(self, tag):
        return hash(str(self.secretkey1)+str(tag)) % (len(self.table[1]))
    
    def insertAllEle(self, tagList, A):
        for i in range(len(A)):
            if self.flag:
                self.insertOneEle(tagList[i], A[i])

    def insertOneEle(self, tag, kv): #key is tag, value is the form of (k,v)
        ins_tag = tag
        ins_kv = kv
        ins_table_num = 0
        Loc = [self.hash_one(ins_tag), self.hash_two(ins_tag)]
        if self.table[0][Loc[0]]==("",("","")):
            self.table[0][Loc[0]]=(ins_tag, ins_kv)
            return
        elif self.table[1][Loc[1]]==("",("","")):
            self.table[1][Loc[1]]=(ins_tag, ins_kv)
            return
        else:
            ins_table_num = random.randint(0, 1)
            (temp_tag, temp_kv) = self.table[ins_table_num][Loc[ins_table_num]]
            self.table[ins_table_num][Loc[ins_table_num]] = (ins_tag, ins_kv)
            (ins_tag, ins_kv) = (temp_tag, temp_kv)
            ins_table_num = ins_table_num^1

        count = 0
        while count<self.threshold_evict-1:
            loc = self.hashfunction[ins_table_num](ins_tag)
            if self.table[ins_table_num][loc]==("",("","")):
                self.table[ins_table_num][loc]=(ins_tag, ins_kv)
                return
            else:
                (temp_tag, temp_kv) = self.table[ins_table_num][loc]
                self.table[ins_table_num][loc] = (ins_tag, ins_kv)
                (ins_tag, ins_kv) = (temp_tag, temp_kv)
                ins_table_num = ins_table_num^1
            count += 1
        if count==self.threshold_evict-1:
            #if len(self.stash)<self.threshold_stash_size:
            self.stash.append((ins_tag,ins_kv))
            #else:
            #    print("fail!!")
            #    self.flag = False

    def lookupWithSecreetkey(self, tag):
        return (self.stash, self.table[0][hash(str(self.secretkey0)+str(tag)) % (len(self.table[0]))], self.table[1][hash(str(self.secretkey1)+str(tag)) % (len(self.table[1]))])

    def lookup(self, LevelCipher, tag):
        secretkey0 = LevelCipher.encrypt(self.add_to_16(str(0)))#get_random_bytes(16)
        secretkey1 = LevelCipher.encrypt(self.add_to_16(str(1)))#get_random_bytes(16)
        #cipher1 = AES.new(secretkey1, AES.MODE_ECB, use_aesni=True)
        #cipher2 = AES.new(secretkey2, AES.MODE_ECB, use_aesni=True)
        return (self.stash, self.table[0][hash(str(secretkey0)+str(tag)) % (len(self.table[0]))], self.table[1][hash(str(secretkey1)+str(tag)) % (len(self.table[1]))])
    
    def getPos(self, LevelCipher, tag):
        secretkey0 = LevelCipher.encrypt(self.add_to_16(str(0)))#get_random_bytes(16)
        secretkey1 = LevelCipher.encrypt(self.add_to_16(str(1)))#get_random_bytes(16)
        #cipher1 = AES.new(secretkey1, AES.MODE_ECB, use_aesni=True)
        #cipher2 = AES.new(secretkey2, AES.MODE_ECB, use_aesni=True)
        return hash(str(secretkey0)+str(tag)) % (len(self.table[0])), hash(str(secretkey1)+str(tag)) % (len(self.table[1]))
    

if __name__=="__main__":

    maxLevelKey = get_random_bytes(16)#b'\xae\xf6}\x00^\xd9\x0cE\x03 \xe5;\xac\xf8L\xfb'#random.randbytes(16)
    print(maxLevelKey)
    maxLevelCipher = AES.new(maxLevelKey, AES.MODE_ECB, use_aesni=True)
    A = []
    tagL = []

    PosOne = []
    PosTwo = []
    
    n = 2**15
    ht = CuckooMap(maxLevelCipher, 1, 0.2, n)
    
    for i in range(n):
        A.append((str(i), str(i)))
        
        #secretkey1 = maxLevelCipher.encrypt(ht.add_to_16(str(0)))#get_random_bytes(16)
        #secretkey2 = maxLevelCipher.encrypt(ht.add_to_16(str(1)))#get_random_bytes(16)
        #cipher1 = AES.new(secretkey1, AES.MODE_ECB, use_aesni=True)
        #cipher2 = AES.new(secretkey2, AES.MODE_ECB, use_aesni=True)
        #PosOne.append(int.from_bytes(cipher1.encrypt(ht.add_to_16(str(str(i)))), 'big', signed=False)%len(ht.table[0]))
        #PosTwo.append(int.from_bytes(cipher2.encrypt(ht.add_to_16(str(str(i)))), 'big', signed=False)%len(ht.table[0]))
        tagL.append(maxLevelCipher.encrypt(ht.add_to_16(str(i+2)))) #int.from_bytes(maxLevelCipher.encrypt(self.add_to_16(str(i+2))), 'big', signed=False)
    
    ht.insertAllEle(tagL, A)
    print(len(ht.stash))

    for i in range(n):
        s, t1, t2 = ht.lookupWithSecreetkey(tagL[i])
        assert(t1==(maxLevelCipher.encrypt(ht.add_to_16(str(i+2))), (str(i), str(i))) or t2==(maxLevelCipher.encrypt(ht.add_to_16(str(i+2))), (str(i), str(i))) or (maxLevelCipher.encrypt(ht.add_to_16(str(i+2))), (str(i), str(i))) in s)
    
    print(sorted(PosOne))
    print(len(ht.table[0]))
    print(len(ht.stash))
    #print(PosTwo)

    