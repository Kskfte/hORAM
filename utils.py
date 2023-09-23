import math
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
class StandardHashwithStash:

    def __init__(self, N, n) -> None:
        self.stash = []
        self.table = [[]]*n
        self.eachBucketCapacity = math.ceil(3*math.log2(N)/(math.log2(math.log2(N))))
        
        self.secretkey = get_random_bytes(16)
        self.cipher = AES.new(self.secretkey, AES.MODE_ECB, use_aesni=True)

    def add_to_16(self, value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)  # 返回bytes    

    def standard_hash(self, key):
        return int.from_bytes(self.cipher.encrypt(self.add_to_16(str(key))), 'big', signed=False) % (len(self.table[0]))

    def insertOneEle(self, key, data):
        loc = self.standard_hash(key)
        if len(self.table) < self.eachBucketCapacity:
            self.table[loc].append(data)
        else:
            self.stash.append(data)

    def lookup(self, key):
        return self.table[self.standard_hash(key)], self.stash

class CuckooMap:

    """
    A Cuckoo map contains two hash tables with each size (1+epsilon)*n and a stash with maximum size O(log n);
    Thus, a cuckoo map consumes the storage with (1+epsilon)*2n + log n. Each lookup consumes bandwith with 2+log n;
    We set the maximum eviction equals to alpha*log(n), the overflow probability less than n^(-O(log n)) for sufficiently large alpha.
    We set alpha = log2(n), epsilon = 0.001
    """
    def __init__(self, alpha, epsilon, n) -> None:
        self.alpha = alpha
        self.epsilon = epsilon
        self.threshold_stash_size = math.ceil(math.log2(n))#10*math.ceil(math.log2(n))
        self.threshold_evict = self.alpha*math.ceil(math.log2(n))	
        self.table = ([None]*(int)((1+self.epsilon)*n), [None]*(int)((1+self.epsilon)*n))
        self.stash = []
        self.hashfunction = (self.hash_one, self.hash_two)
        
        self.secretkey1 = get_random_bytes(16)
        self.secretkey2 = get_random_bytes(16)
        self.cipher1 = AES.new(self.secretkey1, AES.MODE_ECB, use_aesni=True)
        self.cipher2 = AES.new(self.secretkey2, AES.MODE_ECB, use_aesni=True)
        #print(len(self.secretkey1))
        self.flag = True

    def add_to_16(self, value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)  # 返回bytes
    
    def hash_one(self, key):
        return int.from_bytes(self.cipher1.encrypt(self.add_to_16(str(key))), 'big', signed=False) % (len(self.table[0]))
        #return hash(str(key)+'0') % len(self.table[0])

    def hash_two(self, key):
        return int.from_bytes(self.cipher2.encrypt(self.add_to_16(str(key))), 'big', signed=False) % (len(self.table[1]))
        #return hash(str(key)+'1') % len(self.table[1])
    
    def insertAllEle(self, A):
        num = 0
        for (k,v) in A:
            if self.flag:
                self.insertOneEle(k,v)
                num += 1
            else:
                print(num)
                break

    def insertOneEle(self, key, val):
        ins_key = key
        ins_val = val
        ins_table_num = 0
        Loc = [self.hash_one(ins_key), self.hash_two(ins_key)]
        if self.table[0][Loc[0]]==None:
            self.table[0][Loc[0]]=(ins_key, ins_val)
            return
        elif self.table[1][Loc[1]]==None:
            self.table[1][Loc[1]]=(ins_key, ins_val)
            return
        else:
            ins_table_num = random.randint(0, 1)
            (temp_key, temp_val) = self.table[ins_table_num][Loc[ins_table_num]]
            self.table[ins_table_num][Loc[ins_table_num]] = (ins_key, ins_val)
            (ins_key, ins_val) = (temp_key, temp_val)
            ins_table_num = ins_table_num^1

        count = 0
        while count<self.threshold_evict-1:
            loc = self.hashfunction[ins_table_num](ins_key)
            if self.table[ins_table_num][loc]==None:
                self.table[ins_table_num][loc]=(ins_key, ins_val)
                break
            else:
                (temp_key, temp_val) = self.table[ins_table_num][loc]
                self.table[ins_table_num][loc] = (ins_key, ins_val)
                (ins_key, ins_val) = (temp_key, temp_val)
                ins_table_num = ins_table_num^1
            count += 1
        if count==self.threshold_evict-1:
            if len(self.stash)<self.threshold_stash_size:
                self.stash.append((ins_key,ins_val))
            else:
                print("fail!!")
                self.flag = False

    def lookup(self, key):
        return (self.stash, self.table[0][self.hash_one(key)], self.table[1][self.hash_two(key)])

class Bitonic:
        
    """
    decendOrAscend = 0: decending; ascending otherwise
    """
    def __init__(self, A, decendOrAscend) -> None:    
        self.compTimes = 0
        self.bitonicMerge(A, 0, len(A), decendOrAscend)

    def compAndSwap(self, A, i, j, dire):
        self.compTimes += 1
        if (dire==1 and A[i]> A[j]) or (dire==0 and A[i] < A[j]):
            A[i], A[j] = A[j], A[i]
            
    def bitonicToOrder(self, A, start, end, dire):
        #print(A)
        if end-start>1:
            medium = (end-start)>>1
            for i in range(0, medium):
                self.compAndSwap(A, i+start, i+start+medium, dire)
            self.bitonicToOrder(A, start, start+medium, dire)
            self.bitonicToOrder(A, start+medium, end, dire)

    def bitonicMerge(self, A, start, end, dire):
        if end-start>1:
            medium = (end-start)>>1
            self.bitonicMerge(A, start, start+medium, dire)
            self.bitonicMerge(A, start+medium, end, dire^1)
            self.bitonicToOrder(A, start, end, dire)
  

#print(A)
#bitonicToOrder(A, 0, len(A), 1)
#print(A)

# Python program for Bitonic Sort. Note that this program
# works only when size of input is a power of 2.

# The parameter dir indicates the sorting direction, ASCENDING
# or DESCENDING; if (a[i] > a[j]) agrees with the direction,
# then a[i] and a[j] are interchanged.*/


# It recursively sorts a bitonic sequence in ascending order,
# if dir = 1, and in descending order otherwise (means dir=0).
# The sequence to be sorted starts at index position low,
# the parameter cnt is the number of elements to be sorted.

"""

def bitonicMerge(a, low, cnt, dire):
    if cnt > 1:
        k = cnt//2
        for i in range(low , low+k):
            compAndSwap(a, i, i+k, dire)
        bitonicMerge(a, low, k, dire)
        bitonicMerge(a, low+k, k, dire)

# This function first produces a bitonic sequence by recursively
# sorting its two halves in opposite sorting orders, and then
# calls bitonicMerge to make them in the same order
def bitonicSort(a, low, cnt,dire):
    #if cnt - low == 1:
    #	return
    #elif cnt - low == 2:
    #	compAndSwap(a, low, low+1, )
    if cnt > 1:
        k = cnt//2
        bitonicSort(a, low, k, 1)
        bitonicSort(a, low+k, k, 0)
        bitonicMerge(a, low, cnt, dire)

# Caller of bitonicSort for sorting the entire array of length N
# in ASCENDING order
def sort(a,N, up):
    bitonicSort(a,0, N, up)

# Driver code to test above
a = [3, 7, 4, 8, 6, 2, 1, 5]
n = len(a)
up = 1

sort(a, n, up)
print ("Sorted array is")
for i in range(n):
    print("%d" %a[i],end=" ")
    
"""