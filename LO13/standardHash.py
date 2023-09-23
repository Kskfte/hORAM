import math
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import numpy as np

class StandardHashwithStash:
    """
    N: ORAM parameter
    n: hash bucket count each with capacity 3*log(N)/loglog(N)
    stash size: O(log(N))
    """
    """
    Table element form: (str, str, str): (level, levelEpoch, virtualAddress)
    """

    def __init__(self, levelCipher, N, n) -> None:
        self.eachBucketCapacity = math.ceil(3*math.log2(N)/(math.log2(math.log2(N))))
        self.stash = []
        self.table = [[("",("","")) for i in range(self.eachBucketCapacity)] for j in range(n)]
        
        self.secretkey = levelCipher.encrypt(self.add_to_16(str(2)))
        #self.cipher = AES.new(self.secretkey, AES.MODE_ECB, use_aesni=True)

    def add_to_16(self, value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)  # 返回bytes    

    def standard_hash(self, tag):
        return hash(str(self.secretkey)+str(tag)) % (len(self.table))

    def insertAllEle(self, tagList, A):
        for i in range(len(tagList)):
            self.insertOneEle(tagList[i],A[i])
            
    def insertOneEle(self, tag, kv):
        loc = self.standard_hash(tag)
        if ("",("","")) in self.table[loc]:
            self.table[loc][self.table[loc].index(("",("","")))] = (tag, kv)
        else:
            self.stash.append((tag, kv))
            #if(len(self.stash))

    def lookup(self, tag):
        return self.stash, self.table[self.standard_hash(tag)]

    def getPos(self, LevelCipher, tag):
        secretkey = LevelCipher.encrypt(self.add_to_16(str(2)))
        #cipher = AES.new(secretkey, AES.MODE_ECB, use_aesni=True)
        return hash(str(secretkey)+str(tag)) % (len(self.table))
    
if __name__=="__main__":
    A = []
    tagL = []
    
    N = 2**4
    n = (int)(math.pow(math.log2(N), 2))
    for i in range(n):
        A.append((str(i), str(i)))
        tagL.append(str(i+3))
    
    LevelKey = random.randbytes(16)
    LevelCipher = AES.new(LevelKey, AES.MODE_ECB, use_aesni=True)
    ht = StandardHashwithStash(LevelCipher, N, n)
    ht.insertAllEle(tagL, A)
    #print(ht.table)
    for i in range(n):
        pos = ht.getPos(LevelCipher, str(i+3))
        assert((str(i+3),(str(i), str(i))) in ht.table[pos] or (str(i+3),(str(i), str(i))) in ht.stash)
    print(len(ht.table))
    print(len(ht.stash))