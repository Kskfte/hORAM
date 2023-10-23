import math
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import numpy as np
from cuckooHash import CuckooMap
from standardHash import StandardHashwithStash
import copy
from tqdm import tqdm

class dORAM:
    """
    we assume the server stores (tag, (k,v))
    tag = k for dummy elements
    """
    Dummy = -1
    StashDummy = -2
    Empty = ""
    OldEmpty = ""

    #CuckooAlpha = math.ceil(math.log2())
    def __init__(self, N) -> None: #, c, ellCuckoo, countQ, countS, maxLevel all+1 dORAM.OldEmpty
        """
        Store in client
        """
        self.N = N
        self.c = math.ceil(2*math.log2(N))
        self.maxLevel = 1 + math.ceil(math.log2(N/(self.c)))
        self.ellCuckoo = min(self.maxLevel, 1 + math.ceil(math.log2(math.pow(math.log2(N), 6)/2))) # (int)(7*math.log2(math.log2(N)))
        self.countQ = 0
        self.countS = 0
        self.haveEleFlag = [0 for i in range(self.maxLevel+1)]

        self.levelMasterKey = get_random_bytes(16)
        self.levelMasterCipher = AES.new(self.levelMasterKey, AES.MODE_ECB, use_aesni=True)
        self.prfSecretkey = get_random_bytes(16)
        self.prfCipher = AES.new(self.prfSecretkey, AES.MODE_ECB, use_aesni=True)

        """
        Store in servers 
        The first level is the stash: stash0, stash2
        level = 2, 4, 6,..., in S0: server0Table[level//2]
        3, 5, 7,..., in S1: server0Table[(level-1)//2]
        """
        self.stash0 = [("",("","")) for i in range(math.ceil(math.log2(N)))] # element array
        self.stash1 = [("",("","")) for i in range(math.ceil(math.log2(N)))]
        self.server0Table = [None]*(1+(self.maxLevel//2)) # (evenLevel)//2 # element obj.
        self.server1Table = [None]*(1+((self.maxLevel-1)//2)) # (oddLevel-1)//2

        self.cuckooAlpha = math.ceil(math.log2(N))
        self.cuckooEpsilon = 0.01

        """
        Evaluation metrics
        """
        self.blockNum = 0
        self.errorAccess = 0

    def add_to_16(self, value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)  # return in bytes    

    def prfTag(self, Cipher, level, epoch, key):
        return Cipher.encrypt(self.add_to_16(str(level)+str(epoch)+str(key)))
    
    def getEpoch(self, level):
        firstRebuild = math.ceil(math.log2(self.N)*(2**(level-2)))
        if level==self.maxLevel:
            return self.countQ//firstRebuild
        else:
            return (self.countQ-firstRebuild)//(2*firstRebuild)

    def initialization(self, A): # initialize the array A with the form (k, v)
        """
        Client: generate tag and level hash key. 
        """
        nowLevelCapacity = math.ceil(self.c*(2**(self.maxLevel-1)))
        #print(nowLevelCapacity)
        #print(self.maxLevel)
        self.haveEleFlag[self.maxLevel]=1
        tagList = []
        for (k,_) in A:
            tagList.append(self.prfTag(self.prfCipher,self.maxLevel,0,k)) # (sk, level, epoch, keyw)
        #print(tagList)
        maxLevelKey = self.prfTag(self.levelMasterCipher,self.maxLevel,0,0) # (sk, level, epoch, 0)
        maxLevelCipher = AES.new(maxLevelKey, AES.MODE_ECB, use_aesni=True)
        
        """
        Server S_{1-maxLevel%2}: map the element 
        Send tagList, A, maxLevelKey, maxLevelCipher to server S_{1-maxLevel%2}
        """
        if self.maxLevel>>1<<1 == self.maxLevel: # Element should store in S0, first send them to S1 for hash
            """
            S1 hash in temp buffer
            """
            tempTab = CuckooMap(maxLevelCipher, self.cuckooAlpha, self.cuckooEpsilon, nowLevelCapacity)
            tempTab.insertAllEle(tagList, A)
            delta = len(tempTab.stash)
            for _ in range(delta, (int)(2*math.log2(self.N))):
                tempTab.stash.append(("",("","")))
                #self.countS += 1
            random.shuffle(tempTab.stash)
            """
            initialize a new S0 hash table
            """
            self.server0Table[self.maxLevel//2] = CuckooMap(maxLevelCipher, self.cuckooAlpha, self.cuckooEpsilon, nowLevelCapacity) #len(A)
            ########### Interactive with Client ############
            for i in range(len(tempTab.table[0])):
                if tempTab.table[0][i][0]!=dORAM.OldEmpty:
                    self.server0Table[self.maxLevel//2].table[0][i] = tempTab.table[0][i]
                elif tempTab.table[0][i][0]==dORAM.OldEmpty and delta>0:
                    self.server0Table[self.maxLevel//2].table[0][i] = str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty)) 
                    delta -= 1
                    self.countS += 1
                else:
                    self.server0Table[self.maxLevel//2].table[0][i] = str(dORAM.Empty), (str(dORAM.Empty),str(dORAM.Empty))
            
            for i in range(len(tempTab.table[1])):
                if tempTab.table[1][i][0]!=dORAM.OldEmpty:
                    self.server0Table[self.maxLevel//2].table[1][i] = tempTab.table[1][i]
                elif tempTab.table[1][i][0]==dORAM.OldEmpty and delta>0:
                    self.server0Table[self.maxLevel//2].table[1][i] = str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty)) 
                    delta -= 1
                    self.countS += 1
                else: #tag, (k,v)
                    self.server0Table[self.maxLevel//2].table[1][i] = str(dORAM.Empty), (str(dORAM.Empty),str(dORAM.Empty))

            for i in range(len(tempTab.stash)): # stash in S0 or S1
                if i>>1<<1==i:
                    if tempTab.stash[i][0]!=dORAM.OldEmpty:
                        self.stash0[i//2]=tempTab.stash[i]
                    else:
                        self.stash0[i//2]=str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty))
                        self.countS += 1
                else:
                    if tempTab.stash[i][0]!=dORAM.OldEmpty:
                        self.stash1[i//2]=tempTab.stash[i]
                    else:
                        self.countS += 1
                        self.stash1[i//2]=str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty))
        
        else: # Element should store in S1, first send them to S0 for hash
            """
            S0 hash in temp buffer
            """
            tempTab = CuckooMap(maxLevelCipher, self.cuckooAlpha, self.cuckooEpsilon, nowLevelCapacity)
            tempTab.insertAllEle(tagList, A)
            #print(tempTab.stash)
            delta = len(tempTab.stash)
            #print(len(tempTab.stash))
            #print(tempTab.stash)
            for _ in range(delta, (int)(2*math.log2(self.N))):
                tempTab.stash.append(("",("","")))
                #self.countS += 1
            assert len(tempTab.stash)==(int)(2*math.log2(self.N))
            random.shuffle(tempTab.stash)
            #print(len(tempTab.stash))
            #print(len(A))
            """
            initialize a new S1 hash table
            """
            self.server1Table[((self.maxLevel-1)//2)] = CuckooMap(maxLevelCipher, self.cuckooAlpha, self.cuckooEpsilon, nowLevelCapacity)
            ########### Interactive with Client ############
            for i in range(len(tempTab.table[0])):
                if tempTab.table[0][i][0]!=dORAM.OldEmpty:
                    self.server1Table[((self.maxLevel-1)//2)].table[0][i] = tempTab.table[0][i]
                elif tempTab.table[0][i][0]==dORAM.OldEmpty and delta>0:
                    self.server1Table[((self.maxLevel-1)//2)].table[0][i] = str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty)) 
                    delta -= 1
                    self.countS += 1
                else:
                    self.server1Table[((self.maxLevel-1)//2)].table[0][i] = str(dORAM.Empty), (str(dORAM.Empty),str(dORAM.Empty))
            
            for i in range(len(tempTab.table[1])):
                if tempTab.table[1][i][0]!=dORAM.OldEmpty:
                    self.server1Table[((self.maxLevel-1)//2)].table[1][i] = tempTab.table[1][i]
                elif tempTab.table[1][i][0]==dORAM.OldEmpty and delta>0:
                    self.server1Table[((self.maxLevel-1)//2)].table[1][i] = str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty)) 
                    delta -= 1
                    self.countS += 1
                else: #tag, (k,v)
                    self.server1Table[((self.maxLevel-1)//2)].table[1][i] = str(dORAM.Empty), (str(dORAM.Empty),str(dORAM.Empty))

            for i in range(len(tempTab.stash)):#str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty)) 
                if i>>1<<1==i:
                    if tempTab.stash[i][0]!=dORAM.OldEmpty:
                        self.stash0[i//2]=tempTab.stash[i]
                    else:
                        self.stash0[i//2]=str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty))
                        self.countS += 1
                else:
                    if tempTab.stash[i][0]!=dORAM.OldEmpty:
                        self.stash1[i//2]=tempTab.stash[i]
                    else:
                        self.stash1[i//2]=str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty))
                        self.countS += 1
            
    def access(self, op, wrKey, wrVal):
        """
        Step 1: Client allocate a local buffer
        """
        retrievedEle = "",""
        retrievedFlag = 0
        retrievedStashFlag = 0
        """
        Step 2: Access Stash first.
        1. retrieve the element;
        2. overwrite the element.
        """
        whichStash = 0
        whichIndex = 0
        foundSflag = 0
        for i in range(len(self.stash0)):
            _, (kkey, vvalue) = self.stash0[i]
            if foundSflag==0 and vvalue == str(dORAM.Empty):
                ############ find the first empty spot ################
                whichStash = 0
                whichIndex = i
                foundSflag = 1
            if retrievedFlag==0 and kkey==wrKey:
                retrievedEle = (kkey, vvalue)
                retrievedFlag = 1
                retrievedStashFlag = 1
        for i in range(len(self.stash1)):
            _, (kkey, vvalue) = self.stash1[i]
            if foundSflag==0 and vvalue == str(dORAM.Empty):
                whichStash = 1
                whichIndex = i
                foundSflag = 1
            if retrievedFlag==0 and kkey==wrKey:
                retrievedEle = (kkey, vvalue)
                retrievedFlag = 1
                retrievedStashFlag = 1
        ######################## Compute the Step 2 bandwidth overhead: read + write ############################
        self.blockNum = self.blockNum + len(self.stash0)+len(self.stash1)

        """
        Step 3: Access the first ellCuckoo stored in standard hash
        """
        for i in range(2, self.ellCuckoo):
            tmpEpoch = self.getEpoch(i)#(int)((2*self.countQ//(self.c*math.pow(2,i-1))))
            if self.haveEleFlag[i]==0:
                continue
            levelKey = self.prfTag(self.levelMasterCipher,i,tmpEpoch,0) # (sk, level, epoch, 0)
            levelCipher = AES.new(levelKey, AES.MODE_ECB, use_aesni=True)
            queryTag = self.prfTag(self.prfCipher, i, tmpEpoch, wrKey)
            if retrievedFlag==0:
                if i>>1<<1==i: # S0
                    loc = self.server0Table[i//2].getPos(levelCipher, queryTag)
                    eleList = self.server0Table[i//2].table[loc] #ttag, (kkey, vvalue)
                    for j in range(len(eleList)):
                        ttag, (kkey, vvalue) = eleList[j]
                        if wrKey==kkey and retrievedFlag==0:
                            retrievedEle = (kkey, vvalue)
                            retrievedFlag = 1
                            self.server0Table[i//2].table[loc][j] = str(dORAM.Dummy)+str(self.countQ), (str(dORAM.Dummy)+str(self.countQ), str(dORAM.Dummy))
                        else:
                            self.server0Table[i//2].table[loc][j] = ttag, (kkey, vvalue)      
                    ######################## Compute the Step 3 bandwidth overhead: read + write ############################
                    self.blockNum += (2*len(eleList)) #math.ceil(3*math.log2(self.N)/(math.log2(math.log2(self.N))))

                else: # S1
                    loc = self.server1Table[(i-1)//2].getPos(levelCipher, queryTag)
                    eleList = self.server1Table[(i-1)//2].table[loc]
                    for j in range(len(eleList)):
                        ttag, (kkey, vvalue) = eleList[j]
                        if wrKey==kkey and retrievedFlag==0:
                            retrievedEle = (kkey, vvalue)
                            retrievedFlag = 1
                            self.server1Table[(i-1)//2].table[loc][j] = str(dORAM.Dummy)+str(self.countQ), (str(dORAM.Dummy)+str(self.countQ), str(dORAM.Dummy))
                        else:
                            self.server1Table[(i-1)//2].table[loc][j] = ttag, (kkey, vvalue)      
                    ######################## Compute the Step 3 bandwidth overhead: read + write ############################
                    self.blockNum += (2*len(eleList))
            else:
                if i>>1<<1==i: # S0
                    loc = self.server0Table[i//2].getPos(levelCipher, queryTag)
                    eleList = self.server0Table[i//2].table[loc] #ttag, (kkey, vvalue)
                    self.server0Table[i//2].table[loc] = eleList
                    ######################## Compute the Step 3 bandwidth overhead: read + write ############################
                    self.blockNum += (2*len(eleList))
                else: # S1
                    loc = self.server1Table[(i-1)//2].getPos(levelCipher, queryTag)
                    eleList = self.server1Table[(i-1)//2].table[loc] #ttag, (kkey, vvalue)
                    self.server1Table[(i-1)//2].table[loc] = eleList
                    ######################## Compute the Step 3 bandwidth overhead: read + write ############################
                    self.blockNum += (2*len(eleList))
            
           
        """
        Step 4: Access element in cuckoo hash
        """
        for i in range(self.ellCuckoo, self.maxLevel+1):    
            tmpEpoch = self.getEpoch(i)#(int)((2*self.countQ//(self.c*math.pow(2,i-1))))
            #print(self.maxLevel)
            #print(i)
            #print(self.haveEleFlag[i])
            if self.haveEleFlag[i]==0:
                continue
            levelKey = self.prfTag(self.levelMasterCipher,i,tmpEpoch,0) # (sk, level, epoch, 0)
            #print((int)((2*self.countQ//(self.c*math.pow(2,i-1)))))
            levelCipher = AES.new(levelKey, AES.MODE_ECB, use_aesni=True)
            queryTag = self.prfTag(self.prfCipher, i, tmpEpoch, wrKey) # (sk, level, epoch, key)
            if retrievedFlag==0:
                if i>>1<<1==i: # S0
                    loc0, loc1 = self.server0Table[i//2].getPos(levelCipher, queryTag)
                    ttag0, (kkey0, vvalue0) = self.server0Table[i//2].table[0][loc0]
                    ttag1, (kkey1, vvalue1) = self.server0Table[i//2].table[1][loc1]    
                    if kkey0==wrKey:
                        retrievedEle = (kkey0, vvalue0)
                        retrievedFlag = 1
                        self.server0Table[i//2].table[0][loc0] = str(dORAM.Dummy)+str(self.countQ), (str(dORAM.Dummy)+str(self.countQ), str(dORAM.Dummy))
                    else:
                        self.server0Table[i//2].table[0][loc0] = ttag0, (kkey0, vvalue0)
                    if kkey1==wrKey and retrievedFlag==0:
                        retrievedEle = (kkey1, vvalue1)
                        retrievedFlag = 1
                        self.server0Table[i//2].table[1][loc1] = str(dORAM.Dummy)+str(self.countQ), (str(dORAM.Dummy)+str(self.countQ), str(dORAM.Dummy))
                    else:
                        self.server0Table[i//2].table[1][loc1] = ttag1, (kkey1, vvalue1)
                else: # S1 
                    loc0, loc1 = self.server1Table[(i-1)//2].getPos(levelCipher, queryTag)
                    #print(self.server1Table[((self.maxLevel-1)//2)].lookup(levelCipher, self.prfTag(self.prfCipher,self.maxLevel,0,str(5))))
                    ttag0, (kkey0, vvalue0) = self.server1Table[(i-1)//2].table[0][loc0]
                    ttag1, (kkey1, vvalue1) = self.server1Table[(i-1)//2].table[1][loc1]
                    #print((kkey0, vvalue0)) 
                    #print((kkey0, vvalue0))   
                    if kkey0==wrKey:
                        retrievedEle = (kkey0, vvalue0)
                        retrievedFlag = 1
                        self.server1Table[(i-1)//2].table[0][loc0] = str(dORAM.Dummy)+str(self.countQ), (str(dORAM.Dummy)+str(self.countQ), str(dORAM.Dummy))
                    else:
                        self.server1Table[(i-1)//2].table[0][loc0] = ttag0, (kkey0, vvalue0)
                    if kkey1==wrKey and retrievedFlag==0:
                        retrievedEle = (kkey1, vvalue1)
                        retrievedFlag = 1
                        self.server1Table[(i-1)//2].table[1][loc1] = str(dORAM.Dummy)+str(self.countQ), (str(dORAM.Dummy)+str(self.countQ), str(dORAM.Dummy))
                    else:
                        self.server1Table[(i-1)//2].table[1][loc1] = ttag1, (kkey1, vvalue1)
            else:
                if i>>1<<1==i: # S0
                    loc0 = random.randint(0, len(self.server0Table[i//2].table[0])-1)
                    loc1 = random.randint(0, len(self.server0Table[i//2].table[1])-1)
                    ttag0, (kkey0, vvalue0) = self.server0Table[i//2].table[0][loc0]
                    ttag1, (kkey1, vvalue1) = self.server0Table[i//2].table[1][loc1]    

                    self.server0Table[i//2].table[0][loc0] = ttag0, (kkey0, vvalue0)
                    self.server0Table[i//2].table[1][loc1] = ttag1, (kkey1, vvalue1)
                else: # S1
                    loc0 = random.randint(0, len(self.server1Table[(i-1)//2].table[0])-1)
                    loc1 = random.randint(0, len(self.server1Table[(i-1)//2].table[1])-1)
                    ttag0, (kkey0, vvalue0) = self.server1Table[(i-1)//2].table[0][loc0]
                    ttag1, (kkey1, vvalue1) = self.server1Table[(i-1)//2].table[1][loc1] 

                    self.server1Table[(i-1)//2].table[0][loc0] = ttag0, (kkey0, vvalue0)
                    self.server1Table[(i-1)//2].table[1][loc1] = ttag1, (kkey1, vvalue1)
            ######################## Compute the Step 4 bandwidth overhead: read + write ############################
            self.blockNum += (2*2)

        #assert(retrievedFlag==1)
        if retrievedFlag!=1:
            self.errorAccess += 1

        """
        Step 6&7: rewrite the element into stash, actually access all and then rewrite
        """
        if op=='write':
            retrievedEle = wrKey, wrVal
        if retrievedStashFlag==1:
            if whichStash==0:
                self.stash0[whichIndex]=str(dORAM.Dummy)+str(self.countQ), (str(dORAM.Dummy)+str(self.countQ), str(dORAM.Dummy))
            else:
                self.stash1[whichIndex]=str(dORAM.Dummy)+str(self.countQ), (str(dORAM.Dummy)+str(self.countQ), str(dORAM.Dummy))
        else:
            if whichStash==0:
                self.stash0[whichIndex]=str(1), retrievedEle
            else:
                self.stash1[whichIndex]=str(1), retrievedEle
        ######################## Compute the Step 6&7 bandwidth overhead: read + write ############################
        self.blockNum += (2*(len(self.stash0)+len(self.stash1)))
        
        """
        if retrievedStashFlag==1:
            for i in range(len(self.stash0)):
                ttag, (kkey, vvalue) = self.stash0[i]
                if kkey==wrKey:
                    self.stash0[i] = ttag, retrievedEle
                else:
                    self.stash0[i] = ttag, (kkey, vvalue)
            for i in range(len(self.stash1)):
                ttag, (kkey, vvalue) = self.stash1[i]
                if kkey==wrKey:
                    self.stash1[i] = ttag, retrievedEle
                else:
                    self.stash1[i] = ttag, (kkey, vvalue)
        else:
            haveWriteFlag = 0
            for i in range(len(self.stash0)):
                ttag, (kkey, vvalue) = self.stash0[i]
                if vvalue==str(dORAM.Empty) and haveWriteFlag==0:
                    self.stash0[i] = ttag, retrievedEle
                    haveWriteFlag = 1
                else:
                    self.stash0[i] = ttag, (kkey, vvalue)
            for i in range(len(self.stash1)):
                ttag, (kkey, vvalue) = self.stash1[i]
                if vvalue==str(dORAM.Empty) and haveWriteFlag==0:
                    self.stash1[i] = ttag, retrievedEle
                    haveWriteFlag = 1
                else:
                    self.stash1[i] = ttag, (kkey, vvalue)

        """
        

        self.countQ += 1
        rebuildFlag = 0
        if self.countQ%(self.c//2)==0:
            for i in range(2,self.maxLevel+1):
                if self.haveEleFlag[i]==0:
                    #print(i)
                    self.rebuild(i)
                    rebuildFlag = 1
                    break
            if rebuildFlag == 0:
                #print(self.maxLevel)
                self.rebuild(self.maxLevel)

        return retrievedEle

    def rebuild(self, lev):
        rebuildLev = lev
        nowLevelCapacity = math.ceil(self.c*(2**(rebuildLev-1)))
        accessLev = lev
        if lev==self.maxLevel:
            accessLev = lev+1
        if rebuildLev>>1<<1==rebuildLev: # need rebuild in S0
            """
            step 1: S1 send result to client
            """
            tempTabS1 = copy.deepcopy(self.stash1)
            for i in range(3, min(accessLev, self.ellCuckoo)):
                if i>>1<<1!=i:
                    tempTabS1.extend([elee for arr in self.server1Table[(i-1)//2].table for elee in arr])
                    self.haveEleFlag[i] = 0
            for i in range(self.ellCuckoo, accessLev):
                if i>>1<<1!=i:
                    tempTabS1.extend(self.server1Table[(i-1)//2].table[0])
                    tempTabS1.extend(self.server1Table[(i-1)//2].table[1])
                    self.haveEleFlag[i] = 0
            random.shuffle(tempTabS1)
            ######################## Compute the Step 1 bandwidth overhead: read + write ############################
            self.blockNum += len(tempTabS1)

            """
            step 2: simulate the re-encrypt and send
            """
            #for i in range(len(tempTabS1)):
            #    tempTabS1[i]=tempTabS1[i]
            tempTabS00 = tempTabS1
            ######################## Compute the Step 2 bandwidth overhead: read + write ############################
            self.blockNum += len(tempTabS00)
            """
            step 3: S0 re-shuffle
            """
            tempTabS0=tempTabS00
            #print(len(tempTabS0))
            tempTabS0.extend([ele for ele in self.stash0])
            #print(len(tempTabS0))
            for i in range(2, min(accessLev, self.ellCuckoo)):
                if i>>1<<1==i:
                    tempTabS0.extend([elee for arr in self.server0Table[i//2].table for elee in arr])
                    self.haveEleFlag[i] = 0
            for i in range(self.ellCuckoo, accessLev):
                if i>>1<<1==i:
                    tempTabS0.extend(self.server0Table[i//2].table[0])
                    tempTabS0.extend(self.server0Table[i//2].table[1])
                    self.haveEleFlag[i] = 0
            random.shuffle(tempTabS0)
            ######################## Compute the Step 3 bandwidth overhead: read + write ############################
            self.blockNum += len(tempTabS0)
            
            """
            step 4: client remove the empty and re-encrypt the element
            """
            self.haveEleFlag[lev]=1
            nowEpoch = self.getEpoch(lev)#(int)((2*self.countQ//(self.c*math.pow(2,lev-1))))
            levelKey = self.prfTag(self.levelMasterCipher,lev,nowEpoch,0) # (sk, level, epoch, 0)
            levelCipher = AES.new(levelKey, AES.MODE_ECB, use_aesni=True)

            tempStep4ElList = []
            tempStep4TagList = []
            for i in range(len(tempTabS0)):
                #print(tempTabS0[i])
                #print(len(tempTabS0[i]))
                _, (step4Key, step4Ele) = tempTabS0[i]
                if step4Ele!=str(dORAM.Empty):
                    #print(step4Key)
                    tempStep4ElList.append((step4Key, step4Ele))
                    tempStep4TagList.append(self.prfTag(self.prfCipher, lev, nowEpoch, step4Key))
            ######################## Compute the Step 4 bandwidth overhead: read + write ############################
            self.blockNum += len(tempStep4ElList)
            
            """
            step 5: S1 compute the table and send to client
            """
            #print(len(tempTabS0))
            #print(nowLevelCapacity)
            #print(len(tempStep4ElList))
            if lev<self.ellCuckoo:
                tempStep5S1Tab = StandardHashwithStash(levelCipher, self.N, nowLevelCapacity)
                tempStep5S1Tab.insertAllEle(tempStep4TagList, tempStep4ElList)
                delta = len(tempStep5S1Tab.stash)
               
                """
                step 6&7: Client and S0 re-process the element
                """
                
                #print(delta)
                #print((int)(2*math.log2(self.N)))
                for _ in range(delta, (int)(2*math.log2(self.N))):
                    tempStep5S1Tab.stash.append(("",("","")))
                    #self.countS += 1
                random.shuffle(tempStep5S1Tab.stash)

                """
                S1 send to client ######################## Compute the Step 5 bandwidth overhead: read + write ############################
                """
                self.blockNum += (len(tempStep5S1Tab.stash)+len(tempStep5S1Tab.table)*len(tempStep5S1Tab.table[0]))
                #print(tempStep5S1Tab.stash)
                #print(len(tempStep5S1Tab.stash))
                """
                initialize a new S0 hash table
                """
                
                ######################## Client send to S0, Compute the Step 5 bandwidth overhead: read + write ############################
                self.blockNum += (len(tempStep5S1Tab.stash)+len(tempStep5S1Tab.table)*len(tempStep5S1Tab.table[0]))

                self.server0Table[lev//2] = StandardHashwithStash(levelCipher, self.N, nowLevelCapacity)
                ########### Interactive with Client ############
            
                for i in range(len(tempStep5S1Tab.table)):
                    for j in range(len(tempStep5S1Tab.table[i])):
                        if tempStep5S1Tab.table[i][j][0]!=dORAM.OldEmpty:
                            self.server0Table[lev//2].table[i][j] = tempStep5S1Tab.table[i][j]
                        elif tempStep5S1Tab.table[i][j][0]==dORAM.OldEmpty and delta>0:
                            self.server0Table[lev//2].table[i][j] = str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty)) 
                            delta -= 1
                            self.countS += 1
                        else:
                            self.server0Table[lev//2].table[i][j] = str(dORAM.Empty), (str(dORAM.Empty),str(dORAM.Empty))                
            else:
                tempStep5S1Tab = CuckooMap(levelCipher, self.cuckooAlpha, self.cuckooEpsilon, nowLevelCapacity)
                tempStep5S1Tab.insertAllEle(tempStep4TagList, tempStep4ElList)
                delta = len(tempStep5S1Tab.stash)
                
                for _ in range(delta, (int)(2*math.log2(self.N))):
                    tempStep5S1Tab.stash.append(("",("","")))
                    #self.countS += 1
                random.shuffle(tempStep5S1Tab.stash)
                
                ######################## S1 send to client, Compute the Step 5 bandwidth overhead: read + write ############################
                self.blockNum += (len(tempStep5S1Tab.stash)+len(tempStep5S1Tab.table[0])+len(tempStep5S1Tab.table[1]))

                """
                step 6&7: Client and S0 re-process the element
                """
                ######################## Client send to S0, Compute the Step 5 bandwidth overhead: read + write ############################
                self.blockNum += (len(tempStep5S1Tab.stash)+len(tempStep5S1Tab.table[0])+len(tempStep5S1Tab.table[1]))
                """
                initialize a new S0 hash table
                """
                self.server0Table[lev//2] = CuckooMap(levelCipher, self.cuckooAlpha, self.cuckooEpsilon, nowLevelCapacity)
                ########### Interactive with Client ############
            
                for i in range(len(tempStep5S1Tab.table[0])):
                    if tempStep5S1Tab.table[0][i][0]!=dORAM.OldEmpty:
                        self.server0Table[lev//2].table[0][i] = tempStep5S1Tab.table[0][i]
                    elif tempStep5S1Tab.table[0][i][0]==dORAM.OldEmpty and delta>0:
                        self.server0Table[lev//2].table[0][i] = str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty)) 
                        delta -= 1
                        self.countS += 1
                    else:
                        self.server0Table[lev//2].table[0][i] = str(dORAM.Empty), (str(dORAM.Empty),str(dORAM.Empty))
                
                for i in range(len(tempStep5S1Tab.table[1])):
                    if tempStep5S1Tab.table[1][i][0]!=dORAM.OldEmpty:
                        self.server0Table[lev//2].table[1][i] = tempStep5S1Tab.table[1][i]
                    elif tempStep5S1Tab.table[1][i][0]==dORAM.OldEmpty and delta>0:
                        self.server0Table[lev//2].table[1][i] = str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty)) 
                        delta -= 1
                        self.countS += 1
                    else: #tag, (k,v)
                        self.server0Table[lev//2].table[1][i] = str(dORAM.Empty), (str(dORAM.Empty),str(dORAM.Empty))

            for i in range((int)(2*math.log2(self.N))): # stash in S0 or S1 len(tempStep5S1Tab.stash)
                if i>>1<<1==i:
                    if tempStep5S1Tab.stash[i][0]!=dORAM.OldEmpty:
                        self.stash0[i//2]=tempStep5S1Tab.stash[i]
                    else:
                        self.stash0[i//2]=str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty))
                        self.countS += 1
                else:
                    if tempStep5S1Tab.stash[i][0]!=dORAM.OldEmpty:
                        self.stash1[i//2]=tempStep5S1Tab.stash[i]
                    else:
                        self.stash1[i//2]=str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty))
                        self.countS += 1
        

        else:# need rebuild in S1
            """
            step 1: S0 send result to client
            """
            tempTabS0 = copy.deepcopy(self.stash0)
            for i in range(2, min(accessLev, self.ellCuckoo)):
                if i>>1<<1==i:
                    tempTabS0.extend([elee for arr in self.server0Table[i//2].table for elee in arr])
                    self.haveEleFlag[i] = 0
            for i in range(self.ellCuckoo, accessLev):
                if i>>1<<1==i:
                    tempTabS0.extend(self.server0Table[i//2].table[0])
                    tempTabS0.extend(self.server0Table[i//2].table[1])
                    self.haveEleFlag[i] = 0
            random.shuffle(tempTabS0)
            ######################## Compute the Step 1 bandwidth overhead: read + write ############################
            self.blockNum += len(tempTabS0)
            """
            step 2: simulate the re-encrypt
            """
            #for i in range(len(tempTabS0)):
            #    tempTabS0[i]=tempTabS0[i]
            tempTabS11 = tempTabS0
            ######################## Compute the Step 2 bandwidth overhead: read + write ############################
            self.blockNum += len(tempTabS11)
            """
            step 3: S1 re-shuffle
            """
            tempTabS1=tempTabS11
            tempTabS1.extend(self.stash1)
            for i in range(3, min(accessLev, self.ellCuckoo)):
                if i>>1<<1!=i:
                    tempTabS1.extend([elee for arr in self.server1Table[(i-1)//2].table for elee in arr])
                    self.haveEleFlag[i] = 0
            for i in range(self.ellCuckoo, accessLev):
                if i>>1<<1!=i:
                    tempTabS1.extend(self.server1Table[(i-1)//2].table[0])
                    tempTabS1.extend(self.server1Table[(i-1)//2].table[1])
                    self.haveEleFlag[i] = 0
            random.shuffle(tempTabS1)
            ######################## Compute the Step 3 bandwidth overhead: read + write ############################
            self.blockNum += len(tempTabS1)
            """
            step 4: client remove the empty and re-encrypt the element
            """
            self.haveEleFlag[lev]=1
            nowEpoch = self.getEpoch(lev)#(int)((2*self.countQ//(self.c*math.pow(2,lev-1))))
            levelKey = self.prfTag(self.levelMasterCipher,lev,nowEpoch,0) # (sk, level, epoch, 0)
            levelCipher = AES.new(levelKey, AES.MODE_ECB, use_aesni=True)

            tempStep4ElList = []
            tempStep4TagList = []
            for i in range(len(tempTabS1)):
                _, (step4Key, step4Ele) = tempTabS1[i]
                if step4Ele!=str(dORAM.Empty):
                    tempStep4ElList.append((step4Key, step4Ele))
                    tempStep4TagList.append(self.prfTag(self.prfCipher, lev,nowEpoch,step4Key))
            ######################## Compute the Step 4 bandwidth overhead: read + write ############################
            self.blockNum += len(tempStep4ElList)
            """
            step 5: S0 compute the table
            """
            #print(len(tempStep4ElList))
            if lev<self.ellCuckoo:
                tempStep5S0Tab = StandardHashwithStash(levelCipher, self.N, nowLevelCapacity)
                tempStep5S0Tab.insertAllEle(tempStep4TagList, tempStep4ElList)
                delta = len(tempStep5S0Tab.stash)
                for _ in range(delta, (int)(2*math.log2(self.N))):
                    tempStep5S0Tab.stash.append(("",("","")))
                    #self.countS += 1
                random.shuffle(tempStep5S0Tab.stash)
                """
                step 6&7: Client and S1 re-process the element
                """
                
                ######################## S0 to client, Compute the Step 5 bandwidth overhead: read + write ############################
                self.blockNum += (len(tempStep5S0Tab.stash)+len(tempStep5S0Tab.table)*len(tempStep5S0Tab.table[0]))

                
                ######################## client to S1, Compute the Step 5 bandwidth overhead: read + write ############################
                self.blockNum += (len(tempStep5S0Tab.stash)+len(tempStep5S0Tab.table)*len(tempStep5S0Tab.table[0]))

                """
                initialize a new S1 hash table
                """
                self.server1Table[(lev-1)//2] = StandardHashwithStash(levelCipher, self.N, nowLevelCapacity)
                ########### Interactive with Client ############
                
                for i in range(len(tempStep5S0Tab.table)):
                    for j in range(len(tempStep5S0Tab.table[i])):
                        if tempStep5S0Tab.table[i][j][0]!=dORAM.OldEmpty:
                            self.server1Table[(lev-1)//2].table[i][j] = tempStep5S0Tab.table[i][j]
                        elif tempStep5S0Tab.table[i][j][0]==dORAM.OldEmpty and delta>0:
                            self.server1Table[(lev-1)//2].table[i][j] = str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty)) 
                            delta -= 1
                            self.countS += 1
                        else:
                            self.server1Table[(lev-1)//2].table[i][j] = str(dORAM.Empty), (str(dORAM.Empty),str(dORAM.Empty))                
            else:
                
                tempStep5S0Tab = CuckooMap(levelCipher, self.cuckooAlpha, self.cuckooEpsilon, nowLevelCapacity)
                tempStep5S0Tab.insertAllEle(tempStep4TagList, tempStep4ElList)
                delta = len(tempStep5S0Tab.stash)
                
                for _ in range(delta, (int)(2*math.log2(self.N))):
                    tempStep5S0Tab.stash.append(("",("","")))
                    #self.countS += 1
                random.shuffle(tempStep5S0Tab.stash)
                ######################## Compute the Step 5 bandwidth overhead: read + write ############################
                self.blockNum += (len(tempStep5S0Tab.stash)+len(tempStep5S0Tab.table[0])+len(tempStep5S0Tab.table[1]))

                """
                step 6&7: Client and S1 re-process the element
                """
                ######################## Compute the Step 5 bandwidth overhead: read + write ############################
                self.blockNum += (len(tempStep5S0Tab.stash)+len(tempStep5S0Tab.table[0])+len(tempStep5S0Tab.table[1]))
                
                """
                initialize a new S1 hash table
                """
                self.server1Table[(lev-1)//2] = CuckooMap(levelCipher, self.cuckooAlpha, self.cuckooEpsilon, nowLevelCapacity)
                ########### Interactive with Client ############
                
                for i in range(len(tempStep5S0Tab.table[0])):
                    if tempStep5S0Tab.table[0][i][0]!=dORAM.OldEmpty:
                        self.server1Table[(lev-1)//2].table[0][i] = tempStep5S0Tab.table[0][i]
                    elif tempStep5S0Tab.table[0][i][0]==dORAM.OldEmpty and delta>0:
                        self.server1Table[(lev-1)//2].table[0][i] = str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty)) 
                        delta -= 1
                        self.countS += 1
                    else:
                        self.server1Table[(lev-1)//2].table[0][i] = str(dORAM.Empty), (str(dORAM.Empty),str(dORAM.Empty))
                
                for i in range(len(tempStep5S0Tab.table[1])):
                    if tempStep5S0Tab.table[1][i][0]!=dORAM.OldEmpty:
                        self.server1Table[(lev-1)//2].table[1][i] = tempStep5S0Tab.table[1][i]
                    elif tempStep5S0Tab.table[1][i][0]==dORAM.OldEmpty and delta>0:
                        self.server1Table[(lev-1)//2].table[1][i] = str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty)) 
                        delta -= 1
                        self.countS += 1
                    else: #tag, (k,v)
                        self.server1Table[(lev-1)//2].table[1][i] = str(dORAM.Empty), (str(dORAM.Empty),str(dORAM.Empty))

            for i in range((int)(2*math.log2(self.N))): # stash in S0 or S1 len(tempStep5S0Tab.stash)
                if i>>1<<1==i:
                    if tempStep5S0Tab.stash[i][0]!=dORAM.OldEmpty:
                        self.stash0[i//2]=tempStep5S0Tab.stash[i]
                    else:
                        self.stash0[i//2]=str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty))
                        self.countS += 1
                else:
                    if tempStep5S0Tab.stash[i][0]!=dORAM.OldEmpty:
                        self.stash1[i//2]=tempStep5S0Tab.stash[i]
                    else:
                        self.stash1[i//2]=str(dORAM.Dummy)+str(self.countS),(str(dORAM.Dummy)+str(self.countS),str(dORAM.Empty))
                        self.countS += 1

        #print(self.stash0)
        #print(self.stash1)
        self.haveEleFlag[lev] = 1

if __name__=="__main__":
    A = []
    
    N = 2**8
    for i in range(N):
        A.append((str(i), str(i+4)))
    access_times = N//2
    oram = dORAM(N)
    oram.initialization(A)
    pbar = tqdm(total=access_times)
    OP = ["w","r"]
    for i in range(access_times):
        op = random.choice(OP)
        ele = oram.access(op, str(random.randint(0,1)), str(random.randint(0,i)))
        #print((i,ele))
        pbar.update(math.ceil((i+1)/access_times))
    pbar.close()
    print(oram.blockNum)
    print(oram.blockNum/access_times)
    #print(oram.blockNum/((N-1)//2))
    print(oram.errorAccess)
    #print(oram.stash0)
    #print(oram.stash1)
    #print(oram.server1Table[(oram.maxLevel-1)//2].table[0])
    #print(oram.server1Table[(oram.maxLevel-1)//2].table[1])
    #Key = []
    """
    for ele in oram.server1Table[(oram.maxLevel-1)//2].table[0]:
        Key.append(ele[1][0])
    for ele in oram.server1Table[(oram.maxLevel-1)//2].table[1]:
        Key.append(ele[1][0])
    for ele in oram.stash0:
        Key.append(ele[1][0])
    for ele in oram.stash1:
        Key.append(ele[1][0])
    for i in range(N):
        assert(str(i) in Key)
    """
    
    #print(Key) 
    #print(oram.maxLevel)
    #print(oram.ellCuckoo)

        


        

        

        


        