import math
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import numpy as np
from cuckooHashOneOffet import CuckooMap
import copy
import sys
from pir import PIRRead,PIRWrite
from utils import byteXor,strXor
from tqdm import tqdm

class cORAM:
    """
    we assume the server stores (tag, (k,v))
    tag = k for dummy elements
    """
    def __init__(self, N, sizePerBlock) -> None: #, c, ellCuckoo, countQ, countS, maxLevel all+1 dORAM.OldEmpty
        """
        Store in client
        """
        self.sizePerBlock = sizePerBlock 
        self.N = N
        self.L = math.ceil(math.log2(N))
        self.ell = min(self.L-1, math.ceil(2*math.log2(math.log2(N)))) # N: 16, 64, 64*4
        self.ctr = 0
        self.full = [0 for i in range(self.L-self.ell+1)] # 1,2,...
        self.eleEmptyForm = ("-1","-1")
        self.tagEmptyForm = bytes(16)
        self.eleEllEmptyForm = ("-1","-1","-1")
        self.tagEllEmptyForm = (bytes(16),"-1")
        tmp_val = 1
        self.dummyT = tmp_val.to_bytes(8,'big')
        self.dummyE = str(-sys.maxsize)
        self.ellEpoch = 0
        self.ellAccessTimes = 0

        """
        To generate the level key
        """
        self.levelMasterKey = get_random_bytes(16)
        self.levelMasterCipher = AES.new(self.levelMasterKey, AES.MODE_ECB, use_aesni=True)
        """
        To generate the tag
        """
        self.prfSecretkey = get_random_bytes(16)
        self.prfCipher = AES.new(self.prfSecretkey, AES.MODE_ECB, use_aesni=True)

        """
        Store in servers, position 0 of all the table is dummy
        """
        self.ecEllLength = 2**(self.ell+1)+math.ceil(math.log2(N))*(self.L-self.ell)
        self.EC0 = None # store (a, v, levelndex): (str, str, str)
        self.ES0 = [(str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))]
        self.EB0 = [(str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))]
        self.EC1 = None 
        self.ES1 = [(str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))]
        self.EB1 = [(str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))]
        
        self.TC0 = None # store (tag, levelIndex): (16-byte, str)
        self.TS0 = [(get_random_bytes(16),str(random.randint(0,sys.maxsize)))]
        self.TB0 = [(get_random_bytes(16),str(random.randint(0,sys.maxsize)))]
        self.TC1 = None 
        self.TS1 = [(get_random_bytes(16),str(random.randint(0,sys.maxsize)))]
        self.TB1 = [(get_random_bytes(16),str(random.randint(0,sys.maxsize)))]

        self.ET0 = [None]*(self.L-self.ell+1)
        self.TT0 = [None]*(self.L-self.ell+1)
        self.ET1 = [None]*(self.L-self.ell+1)
        self.TT1 = [None]*(self.L-self.ell+1)

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

    def generateTag(self, key):
        return self.prfCipher.encrypt(self.add_to_16(str(key)))[:16]

    def generateLevelCipher(self, level, epoch):
        tmpKey = self.levelMasterCipher.encrypt(self.add_to_16(str(level)+str(epoch)))
        return  AES.new(tmpKey, AES.MODE_ECB, use_aesni=True)
    
    def getEpoch(self, level):
        if level==self.ell:
            return self.ellEpoch#(self.ctr)//(2*(2**level)) + self.ctr//math.ceil(math.log2(self.N))
        elif level==self.L:
            return self.ctr//(2**level)
        else:
            assert self.ctr>=2**level
            return max(0, (self.ctr-2**level))//(2*(2**level))

    def subRebuildFL(self, tagList, eleList_0, eleList_1, shareTagList_0, shareTagList_1):
        """
        Bandwidth here: 
        Server 0 sends tagArea0 and eleArea0, receive new tagArea0 and eleArea0;
        Server 1 sends tagArea1, receive new tagArea1 and eleArea1;
        """
        self.blockNum = self.blockNum + 6*len(tagList)
        self.ellEpoch += 1
        self.ellAccessTimes = 0

        newEllLevCipher = self.generateLevelCipher(self.ell, self.getEpoch(self.ell))
        #print("RebuildEpochEll:{}".format(self.getEpoch(self.ell)))
        #print(tagList)
        for i in range(len(tagList)):
            assert tagList[i]==byteXor(shareTagList_0[i][0],shareTagList_1[i][0])
        #print(eleList_0)
        #print(eleList_1)
        self.EC0 = CuckooMap(newEllLevCipher,self.cuckooAlpha,self.cuckooEpsilon,self.ecEllLength,self.eleEllEmptyForm)
        self.ES0 = [(str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))]
        self.EB0 = [(str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))]
        
        self.TC0 = CuckooMap(newEllLevCipher,self.cuckooAlpha,self.cuckooEpsilon,self.ecEllLength,self.tagEllEmptyForm)
        self.TS0 = [(get_random_bytes(16),str(random.randint(0,sys.maxsize)))]
        self.TB0 = [(get_random_bytes(16),str(random.randint(0,sys.maxsize)))]

        self.EC1 = CuckooMap(newEllLevCipher,self.cuckooAlpha,self.cuckooEpsilon,self.ecEllLength,self.eleEllEmptyForm)
        self.ES1 = [(str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))]
        self.EB1 = [(str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))]
        
        self.TC1 = CuckooMap(newEllLevCipher,self.cuckooAlpha,self.cuckooEpsilon,self.ecEllLength,self.tagEllEmptyForm)
        self.TS1 = [(get_random_bytes(16),str(random.randint(0,sys.maxsize)))]
        self.TB1 = [(get_random_bytes(16),str(random.randint(0,sys.maxsize)))]

        #print(len(tagList))
        self.EC0.insertAllEle(tagList, eleList_0)
        #print(self.EC0.stash)
        self.ES0.extend(self.EC0.stash)
        #self.EB0 = [(str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))]
        self.TC0.insertAllEle(tagList, shareTagList_0)
        #print(self.TC0.stash)
        self.TS0.extend(self.TC0.stash)
        #self.TB0 = [(get_random_bytes(16),str(random.randint(0,sys.maxsize)))]

        self.EC1.insertAllEle(tagList, eleList_1)
        self.ES1.extend(self.EC1.stash)
        #self.EB1 = [(str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)),str(random.randint(0,sys.maxsize)))]
        self.TC1.insertAllEle(tagList, shareTagList_1)
        self.TS1.extend(self.TC1.stash)
        #for i in range(len(self.EC0.table[0])):
        #    assert self.EC0.table[0][i]==self.EC1.table[0][i] and self.EC0.table[1][i]==self.EC1.table[1][i]
        #self.TB1 = [(get_random_bytes(16),str(random.randint(0,sys.maxsize)))]
        #print(self.EC0.table[0])
        #print(self.EC0.table[1])

    def subRebuild(self, nowLevel, tagList, eleList_0, eleList_1, shareTagList_0, shareTagList_1):
        
        """
        Bandwidth here
        """
        self.blockNum = self.blockNum + 6*(len(tagList))

        #ellLevelCipher = self.generateLevelCipher(self.ell,0)
        LLevelCipher = self.generateLevelCipher(nowLevel,self.getEpoch(nowLevel))
        self.ET0[nowLevel-self.ell] = CuckooMap(LLevelCipher,self.cuckooAlpha,self.cuckooEpsilon,self.N,self.eleEmptyForm)
        self.TT0[nowLevel-self.ell] = CuckooMap(LLevelCipher,self.cuckooAlpha,self.cuckooEpsilon,self.N,self.tagEmptyForm)
        self.ET1[nowLevel-self.ell] = CuckooMap(LLevelCipher,self.cuckooAlpha,self.cuckooEpsilon,self.N,self.eleEmptyForm)
        self.TT1[nowLevel-self.ell] = CuckooMap(LLevelCipher,self.cuckooAlpha,self.cuckooEpsilon,self.N,self.tagEmptyForm)

        self.ET0[nowLevel-self.ell].insertAllEle(tagList, eleList_0)
        self.TT0[nowLevel-self.ell].insertAllEle(tagList, shareTagList_0)
        self.ET1[nowLevel-self.ell].insertAllEle(tagList, eleList_1)
        self.TT1[nowLevel-self.ell].insertAllEle(tagList, shareTagList_1)

        if len(self.ET0[nowLevel-self.ell].stash)!=0:
            tmpTagList = []
            tmpEleList_0 = []
            tmpEleList_1 = []
            tmpTagList_0 = []
            tmpTagList_1 = []
            for i in range(len(self.TT0[nowLevel-self.ell].stash)):
                tmpTag = byteXor(self.TT0[nowLevel-self.ell].stash[i], self.TT1[nowLevel-self.ell].stash[i])
                tmpTagList.append(tmpTag)
                tmpEleList_0.append((self.ET0[nowLevel-self.ell].stash[i][0], self.ET0[nowLevel-self.ell].stash[i][1], str(nowLevel)))
                tmpEleList_1.append((self.ET1[nowLevel-self.ell].stash[i][0], self.ET1[nowLevel-self.ell].stash[i][1], str(nowLevel)))
                tmp_tag_0 = get_random_bytes(16)
                tmp_tag_1 = byteXor(tmpTag, tmp_tag_0)
                tmp_level_0 = random.randint(0,sys.maxsize)
                tmp_level_1 = tmp_level_0^nowLevel
                tmpTagList_0.append((tmp_tag_0,tmp_level_0))
                tmpTagList_1.append((tmp_tag_1,tmp_level_1))
            self.EC0.insertAllEle(tmpTagList, tmpEleList_0)
            self.ES0.extend(self.EC0.stash)
            self.TC0.insertAllEle(tmpTagList, tmpTagList_0)
            self.TS0.extend(self.TC0.stash)
            self.EC1.insertAllEle(tmpTagList, tmpEleList_1)
            self.ES1.extend(self.EC1.stash)
            self.TC1.insertAllEle(tmpTagList, tmpTagList_1)
            self.TS1.extend(self.TC1.stash)
            """
            Bandwidth here: client actually send one EC.element and decide by observing whether it is in stash
            """
            self.blockNum = self.blockNum + len(self.EC0.stash)

        self.full[nowLevel-self.ell] = 1

    
    def initialization(self, A):
        tagList = []
        eleList_0 = []
        eleList_1 = []
        shareTagList_0 = []
        shareTagList_1 = []

        for (k,v) in A:
            tag = self.generateTag(k)
            tag_0 = get_random_bytes(16)
            tag_1 = byteXor(tag, tag_0)
            tagList.append(self.generateTag(k))
            eleList_0.append((str(k),str(v))) 
            eleList_1.append((str(k),str(v))) 
            shareTagList_0.append(tag_0)
            shareTagList_1.append(tag_1)
        
        ellLevelCipher = self.generateLevelCipher(self.ell,0)
        LLevelCipher = self.generateLevelCipher(self.L,0)
        #print(LLevelCipher)
        self.EC0 = CuckooMap(ellLevelCipher,self.cuckooAlpha,self.cuckooEpsilon,self.ecEllLength,self.eleEllEmptyForm)
        self.TC0 = CuckooMap(ellLevelCipher,self.cuckooAlpha,self.cuckooEpsilon,self.ecEllLength,self.tagEllEmptyForm)
        self.ET0[self.L-self.ell] = CuckooMap(LLevelCipher,self.cuckooAlpha,self.cuckooEpsilon,self.N,self.eleEmptyForm)
        self.TT0[self.L-self.ell] = CuckooMap(LLevelCipher,self.cuckooAlpha,self.cuckooEpsilon,self.N,self.tagEmptyForm)

        self.EC1 = CuckooMap(ellLevelCipher,self.cuckooAlpha,self.cuckooEpsilon,self.ecEllLength,self.eleEllEmptyForm)
        self.TC1 = CuckooMap(ellLevelCipher,self.cuckooAlpha,self.cuckooEpsilon,self.ecEllLength,self.tagEllEmptyForm)
        self.ET1[self.L-self.ell] = CuckooMap(LLevelCipher,self.cuckooAlpha,self.cuckooEpsilon,self.N,self.eleEmptyForm)
        self.TT1[self.L-self.ell] = CuckooMap(LLevelCipher,self.cuckooAlpha,self.cuckooEpsilon,self.N,self.tagEmptyForm)

        self.ET0[self.L-self.ell].insertAllEle(tagList, eleList_0)
        self.TT0[self.L-self.ell].insertAllEle(tagList, shareTagList_0)
        self.ET1[self.L-self.ell].insertAllEle(tagList, eleList_1)
        self.TT1[self.L-self.ell].insertAllEle(tagList, shareTagList_1)

        for i in range(len(self.ET0[self.L-self.ell].table[0])):
            assert self.ET0[self.L-self.ell].table[0][i] == self.ET1[self.L-self.ell].table[0][i]

        if len(self.ET0[self.L-self.ell].stash)!=0:
            tmpTagList = []
            tmpEleList_0 = []
            tmpEleList_1 = []
            tmpTagList_0 = []
            tmpTagList_1 = []
            for i in range(len(self.TT0[self.L-self.ell].stash)):
                tmpTag = byteXor(self.TT0[self.L-self.ell].stash[i], self.TT1[self.L-self.ell].stash[i])
                tmpTagList.append(tmpTag)
                tmpEleList_0.append((self.ET0[self.L-self.ell].stash[i][0], self.ET0[self.L-self.ell].stash[i][1], str(self.L)))
                tmpEleList_1.append((self.ET1[self.L-self.ell].stash[i][0], self.ET1[self.L-self.ell].stash[i][1], str(self.L)))
                tmp_tag_0 = get_random_bytes(16)
                tmp_tag_1 = byteXor(tmpTag, tmp_tag_0)
                tmp_level_0 = random.randint(0,sys.maxsize)
                tmp_level_1 = tmp_level_0^self.L
                tmpTagList_0.append((tmp_tag_0,tmp_level_0))
                tmpTagList_1.append((tmp_tag_1,tmp_level_1))
            self.EC0.insertAllEle(tmpTagList, tmpEleList_0)
            self.ES0.extend(self.EC0.stash)
            self.TC0.insertAllEle(tmpTagList, tmpTagList_0)
            self.TS0.extend(self.TC0.stash)
            self.EC1.insertAllEle(tmpTagList, tmpEleList_1)
            self.ES1.extend(self.EC1.stash)
            self.TC1.insertAllEle(tmpTagList, tmpTagList_1)
            self.TS1.extend(self.TC1.stash)

        self.full[self.L-self.ell] = 1

    def access(self, op, a, writeV):
        found = False
        tag = self.generateTag(a)
        retrievedEle = ("-1","-1","-1")
        if len(self.EB0)>1:
            flagEB = False
            temp_pos = -1
            for i in range(len(self.EB0)-1, 0, -1):
                if (not found) and self.EB0[i][0]==a:
                    retrievedEle = self.EB0[i]
                    temp_pos = i
                    found = True
                    flagEB = True
            if flagEB:
                PIRWrite(self.TB0,self.TB1,2).write(temp_pos,(tag,retrievedEle[2]),(self.dummyT+self.ctr.to_bytes(8,'big'),retrievedEle[2]))
            else:
                PIRWrite(self.TB0,self.TB1,2).write(0,(get_random_bytes(16),retrievedEle[2]),(get_random_bytes(16),retrievedEle[2]))
            """
            Bandwidth here: notice two-server
            """
            if self.sizePerBlock=="O(log N)":
                self.blockNum = self.blockNum + len(self.EB0)-1 + 2*(math.ceil(math.log2(len(self.EB0)))+1)
            else:
                self.blockNum = self.blockNum + len(self.EB0)-1 + 2*(1+1)

        if len(self.ES0)>1:
            flagES = False
            temp_pos = -1
            for i in range(1,len(self.ES0)):
                if (not found) and self.ES0[i][0]==a:
                    retrievedEle = self.ES0[i]
                    temp_pos = i
                    found = True
                    flagES = True
            if flagES:
                PIRWrite(self.TS0,self.TS1,2).write(temp_pos,(tag,retrievedEle[2]),(self.dummyT+self.ctr.to_bytes(8,'big'),retrievedEle[2]))
            else:
                PIRWrite(self.TS0,self.TS1,2).write(0,(get_random_bytes(16),retrievedEle[2]),(get_random_bytes(16),retrievedEle[2]))
            """
            Bandwidth here
            """
            if self.sizePerBlock=="O(log N)":
                self.blockNum = self.blockNum + len(self.ES0)-1 + 2*(math.ceil(math.log2(len(self.ES0)))+1)
            else:
                self.blockNum = self.blockNum + len(self.ES0)-1 + 2*(1+1)


        ellLevelCipher = self.generateLevelCipher(self.ell, self.getEpoch(self.ell))
        #print("AccessEpochEll:{}".format(self.getEpoch(self.ell)))
        pos_0, pos_1 = self.EC0.getPos(ellLevelCipher, tag)
        temp_data_0 = PIRRead(self.EC0.table[0], self.EC1.table[0],3).read(pos_0)
        #print(self.EC0.table[0][pos_0])
        #print(temp_data_0)
        if (not found) and temp_data_0[0]==a:
            retrievedEle = temp_data_0
            found = True
            PIRWrite(self.TC0.table[0],self.TC1.table[0],2).write(pos_0,(tag,retrievedEle[2]),(self.dummyT+self.ctr.to_bytes(8,'big'),retrievedEle[2]))
        else:
            #print(self.TC0.table[0])
            PIRWrite(self.TC0.table[0],self.TC1.table[0],2).write(0,(get_random_bytes(16),retrievedEle[2]),(get_random_bytes(16),retrievedEle[2]))
        
        temp_data_1 = PIRRead(self.EC0.table[1], self.EC1.table[1],3).read(pos_1)
        #print(self.EC0.table[1][pos_1])
        #print(temp_data_1)
        if (not found) and temp_data_1[0]==a:
            retrievedEle = temp_data_1
            found = True
            PIRWrite(self.TC0.table[1],self.TC1.table[1],2).write(pos_1,(tag,retrievedEle[2]),(self.dummyT+self.ctr.to_bytes(8,'big'),retrievedEle[2]))
        else:
            PIRWrite(self.TC0.table[1],self.TC1.table[1],2).write(0,(get_random_bytes(16),retrievedEle[2]),(get_random_bytes(16),retrievedEle[2]))

        """
        Bandwidth here
        """
        if self.sizePerBlock=="O(log N)":
            self.blockNum = self.blockNum + 2*(math.ceil(math.log2(len(self.EC0.table[0])))+1) + 2*(math.ceil(math.log2(len(self.TC0.table[0])))+1)
        else:
            self.blockNum = self.blockNum + 2*(1+1) + 2*(1+1)

        #print(self.full[self.L-self.ell])
        for lev in range(self.ell+1,self.L+1):
            if self.full[lev-self.ell]==0:
                continue
            levelCipher = self.generateLevelCipher(lev, self.getEpoch(lev))
            #print(levelCipher)
            #print(self.getEpoch(lev))
            pos_0, pos_1 = self.ET0[lev-self.ell].getPos(levelCipher, tag)

            #print(pos_0)
            #print(pos_1)
            #assert 

            tmp_data_0 = PIRRead(self.ET0[lev-self.ell].table[0], self.ET1[lev-self.ell].table[0], 2).read(pos_0)
            #print(self.ET0[lev-self.ell].table[0][pos_0])
            #print(tmp_data_0)
            if (not found) and tmp_data_0[0]==a:
                retrievedEle = (tmp_data_0[0],tmp_data_0[1],str(lev))
                found = True
                PIRWrite(self.TT0[lev-self.ell].table[0],self.TT1[lev-self.ell].table[0],1).write(pos_0,tag,self.dummyT+self.ctr.to_bytes(8,'big'))
            else:
                PIRWrite(self.TT0[lev-self.ell].table[0],self.TT1[lev-self.ell].table[0],1).write(0,get_random_bytes(16),get_random_bytes(16))
                
            tmp_data_1 = PIRRead(self.ET0[lev-self.ell].table[1], self.ET1[lev-self.ell].table[1], 2).read(pos_1)
            if (not found) and tmp_data_1[0]==a:
                retrievedEle = (tmp_data_1[0],tmp_data_1[1],str(lev))
                found = True
                PIRWrite(self.TT0[lev-self.ell].table[1],self.TT1[lev-self.ell].table[1],1).write(pos_1,tag,self.dummyT+self.ctr.to_bytes(8,'big'))
            else:
                PIRWrite(self.TT0[lev-self.ell].table[1],self.TT1[lev-self.ell].table[1],1).write(0,get_random_bytes(16),get_random_bytes(16))
            """
            Bandwidth here
            """
            if self.sizePerBlock=="O(log N)":
                self.blockNum = self.blockNum + 2*(math.ceil(math.log2(len(self.ET0[lev-self.ell].table[0])))+1) + 2*(math.ceil(math.log2(len(self.TT0[lev-self.ell].table[0])))+1)
            else:
                self.blockNum = self.blockNum + 2*(1+1) + 2*(1+1)


        #print(retrievedEle)
        returnEle = (retrievedEle[0], retrievedEle[1], retrievedEle[2])
        retrievedEle = (retrievedEle[0], retrievedEle[1], str(self.ell))
        if op == "w":
            retrievedEle = (retrievedEle[0], writeV, str(self.ell))
        """
        Bandwidth here
        """
        self.blockNum += 3

        self.EB0.append(retrievedEle)
        self.EB1.append(retrievedEle)

        tag_0 = get_random_bytes(16)
        tag_1 = byteXor(tag, tag_0)
        level_0 = str(random.randint(0,sys.maxsize))
        level_1 = strXor(retrievedEle[2],level_0)
        self.TB0.append((tag_0,level_0))
        self.TB1.append((tag_1,level_1))

        self.ctr += 1
        self.ellAccessTimes += 1
        #print("GlobalCounter:{}".format(self.ctr))
        #print("ReEle:{}".format(returnEle))
        if self.ctr % (2**(self.ell+1)) == 0:
            for j in range(self.ell+1, self.L+1):
                if self.full[j-self.ell]==0:
                    self.rebuild(j)
                    self.full[j-self.ell]=1
                    break
            return returnEle

        if self.ellAccessTimes!=0 and self.ellAccessTimes % math.ceil(math.log2(self.N)) == 0:
            self.rebuildFL()
        
        return returnEle
    
    def rebuildFL(self):
        tagList = []
        eleList_0 = []
        eleList_1 = []
        shareTagList_0 = []
        shareTagList_1 = []
        for i in range(1, len(self.TC0.table[0])):
            temp_level = strXor(self.TC0.table[0][i][1],self.TC1.table[0][i][1]) # (tag, levelIndex)
            if temp_level!="0":
                temp_tag = byteXor(self.TC0.table[0][i][0],self.TC1.table[0][i][0])
                tagList.append(temp_tag)
                if temp_tag[:8]==self.dummyT:
                    tempp_ele = (self.dummyE+str(int.from_bytes(temp_tag[8:], 'big',signed=False)),str(random.randint(0,sys.maxsize)),self.EC0.table[0][i][2])
                    eleList_0.append(tempp_ele)
                    eleList_1.append(tempp_ele)
                else:    
                    eleList_0.append(self.EC0.table[0][i])
                    eleList_1.append(self.EC1.table[0][i])

                temp_tag_0 = get_random_bytes(16)
                temp_tag_1 = byteXor(temp_tag, temp_tag_0)
                temp_level_0 = str(random.randint(0,sys.maxsize))
                temp_level_1 = strXor(temp_level, temp_level_0)
                shareTagList_0.append((temp_tag_0, temp_level_0))
                shareTagList_1.append((temp_tag_1, temp_level_1))
                
            temp_level = strXor(self.TC0.table[1][i][1],self.TC1.table[1][i][1]) # (tag, levelIndex)
            if temp_level!="0":
                temp_tag = byteXor(self.TC0.table[1][i][0],self.TC1.table[1][i][0])
                tagList.append(temp_tag)
                
                if temp_tag[:8]==self.dummyT:
                    tempp_ele = (self.dummyE+str(int.from_bytes(temp_tag[8:], 'big',signed=False)),str(random.randint(0,sys.maxsize)),self.EC0.table[1][i][2])
                    eleList_0.append(tempp_ele)
                    eleList_1.append(tempp_ele)
                else:    
                    eleList_0.append(self.EC0.table[1][i])
                    eleList_1.append(self.EC1.table[1][i])

                temp_tag_0 = get_random_bytes(16)
                temp_tag_1 = byteXor(temp_tag, temp_tag_0)
                temp_level_0 = str(random.randint(0,sys.maxsize))
                temp_level_1 = strXor(temp_level, temp_level_0)
                shareTagList_0.append((temp_tag_0, temp_level_0))
                shareTagList_1.append((temp_tag_1, temp_level_1))

        #temp_alaldl =[]
        #print(self.TC0.table[0])
        #print(self.TC1.table[0])
        #for i in range(1,len(self.TC0.table[0])):
            #temp_alaldl.append(strXor(self.TC0.table[0][i][1],self.TC1.table[0][i][1]))
            #temp_alaldl.append(strXor(self.TC0.table[1][i][1],self.TC1.table[1][i][1]))
            #temp_alaldl.append(byteXor(self.TC0.table[0][i][0],self.TC1.table[0][i][0]))
            #temp_alaldl.append(byteXor(self.TC0.table[1][i][0],self.TC1.table[1][i][0]))
        #print(len(tagList))
        #print(temp_alaldl)

        for i in range(1, len(self.TS0)):
            temp_level = strXor(self.TS0[i][1],self.TS1[i][1])
            if temp_level!="0":
                temp_tag = byteXor(self.TS0[i][0],self.TS1[i][0])
                tagList.append(temp_tag)
                if temp_tag[:8]==self.dummyT:
                    tempp_ele = (self.dummyE+str(int.from_bytes(temp_tag[8:], 'big',signed=False)),str(random.randint(0,sys.maxsize)),self.ES0[i][2])
                    eleList_0.append(tempp_ele)
                    eleList_1.append(tempp_ele)
                else:    
                    eleList_0.append(self.ES0[i])
                    eleList_1.append(self.ES1[i])

                temp_tag_0 = get_random_bytes(16)
                temp_tag_1 = byteXor(temp_tag, temp_tag_0)
                temp_level_0 = str(random.randint(0,sys.maxsize))
                temp_level_1 = strXor(temp_level, temp_level_0)
                shareTagList_0.append((temp_tag_0, temp_level_0))
                shareTagList_1.append((temp_tag_1, temp_level_1))

        for i in range(1, len(self.TB0)):
            temp_level = strXor(self.TB0[i][1],self.TB1[i][1])
            if temp_level!="0":
                temp_tag = byteXor(self.TB0[i][0],self.TB1[i][0])
                tagList.append(temp_tag)
                if temp_tag[:8]==self.dummyT:
                    tempp_ele = (self.dummyE+str(int.from_bytes(temp_tag[8:], 'big',signed=False)),str(random.randint(0,sys.maxsize)),self.EB0[i][2])
                    eleList_0.append(tempp_ele)
                    eleList_1.append(tempp_ele)
                else:    
                    eleList_0.append(self.EB0[i])
                    eleList_1.append(self.EB1[i])

                temp_tag_0 = get_random_bytes(16)
                temp_tag_1 = byteXor(temp_tag, temp_tag_0)
                temp_level_0 = str(random.randint(0,sys.maxsize))
                temp_level_1 = strXor(temp_level, temp_level_0)
                shareTagList_0.append((temp_tag_0, temp_level_0))
                shareTagList_1.append((temp_tag_1, temp_level_1))
        #print(len(self.TS0))
        #print(len(self.ES0))
        #print(tagList)
        #print(eleList_0)
        self.subRebuildFL(tagList, eleList_0, eleList_1, shareTagList_0, shareTagList_1)
        #print(len(self.TS0))
        #print(len(self.ES0))

    def rebuild(self, llev):
        lev=llev
        if llev==self.L:
            lev=llev+1
        tagLevList = []
        eleLevList_0 = []
        eleLevList_1 = []
        shareLevTagList_0 = []
        shareLevTagList_1 = []
        
        tagEllList = []
        eleEllList_0 = []
        eleEllList_1 = []
        shareEllTagList_0 = []
        shareEllTagList_1 = []
        for i in range(1, len(self.TC0.table[0])):
            temp_level = strXor(self.TC0.table[0][i][1],self.TC1.table[0][i][1]) # (tag, levelIndex)
            if temp_level!="0":
                temp_tag = byteXor(self.TC0.table[0][i][0],self.TC1.table[0][i][0])
                if int(temp_level)<lev:
                    tagLevList.append(temp_tag)
                    if temp_tag[:8]==self.dummyT:
                        tempp_ele = (self.dummyE+str(int.from_bytes(temp_tag[8:], 'big',signed=False)),str(random.randint(0,sys.maxsize)))
                        eleLevList_0.append(tempp_ele)
                        eleLevList_1.append(tempp_ele)
                    else:    
                        eleLevList_0.append((self.EC0.table[0][i][0],self.EC0.table[0][i][1]))
                        eleLevList_1.append((self.EC1.table[0][i][0],self.EC1.table[0][i][1]))

                    temp_tag_0 = get_random_bytes(16)
                    temp_tag_1 = byteXor(temp_tag, temp_tag_0)
                    shareLevTagList_0.append(temp_tag_0)
                    shareLevTagList_1.append(temp_tag_1)
                else:
                    tagEllList.append(temp_tag)
                    if temp_tag[:8]==self.dummyT:
                        tempp_ele = (self.dummyE+str(int.from_bytes(temp_tag[8:], 'big',signed=False)),str(random.randint(0,sys.maxsize)),self.EC0.table[0][i][2])
                        eleEllList_0.append(tempp_ele)
                        eleEllList_1.append(tempp_ele)
                    else:    
                        eleEllList_0.append(self.EC0.table[0][i])
                        eleEllList_1.append(self.EC1.table[0][i])

                    temp_tag_0 = get_random_bytes(16)
                    temp_tag_1 = byteXor(temp_tag, temp_tag_0)
                    temp_level_0 = str(random.randint(0,sys.maxsize))
                    temp_level_1 = strXor(temp_level, temp_level_0)
                    shareEllTagList_0.append((temp_tag_0, temp_level_0))
                    shareEllTagList_1.append((temp_tag_1, temp_level_1))
                    
                
            temp_level = strXor(self.TC0.table[1][i][1],self.TC1.table[1][i][1]) # (tag, levelIndex)
            if temp_level!="0":
                temp_tag = byteXor(self.TC0.table[1][i][0],self.TC1.table[1][i][0])
                if int(temp_level)<lev:
                    tagLevList.append(temp_tag)
                    
                    if temp_tag[:8]==self.dummyT:
                        tempp_ele = (self.dummyE+str(int.from_bytes(temp_tag[8:], 'big',signed=False)),str(random.randint(0,sys.maxsize)))
                        eleLevList_0.append(tempp_ele)
                        eleLevList_1.append(tempp_ele)
                    else:    
                        eleLevList_0.append((self.EC0.table[1][i][0],self.EC0.table[1][i][1]))
                        eleLevList_1.append((self.EC1.table[1][i][0],self.EC1.table[1][i][1]))

                    temp_tag_0 = get_random_bytes(16)
                    temp_tag_1 = byteXor(temp_tag, temp_tag_0)
                    shareLevTagList_0.append(temp_tag_0)
                    shareLevTagList_1.append(temp_tag_1)
                else:
                    tagEllList.append(temp_tag)
                    
                    if temp_tag[:8]==self.dummyT:
                        tempp_ele = (self.dummyE+str(int.from_bytes(temp_tag[8:], 'big',signed=False)),str(random.randint(0,sys.maxsize)),self.EC0.table[1][i][2])
                        eleEllList_0.append(tempp_ele)
                        eleEllList_1.append(tempp_ele)
                    else:    
                        eleEllList_0.append(self.EC0.table[1][i])
                        eleEllList_1.append(self.EC1.table[1][i])

                    temp_tag_0 = get_random_bytes(16)
                    temp_tag_1 = byteXor(temp_tag, temp_tag_0)
                    temp_level_0 = str(random.randint(0,sys.maxsize))
                    temp_level_1 = strXor(temp_level, temp_level_0)
                    shareEllTagList_0.append((temp_tag_0, temp_level_0))
                    shareEllTagList_1.append((temp_tag_1, temp_level_1))

        for i in range(1, len(self.TS0)):
            temp_level = strXor(self.TS0[i][1],self.TS1[i][1])
            if temp_level!="0":
                temp_tag = byteXor(self.TS0[i][0],self.TS1[i][0])
                if int(temp_level)<lev:
                    tagLevList.append(temp_tag)
                    if temp_tag[:8]==self.dummyT:
                        tempp_ele = (self.dummyE+str(int.from_bytes(temp_tag[8:], 'big',signed=False)),str(random.randint(0,sys.maxsize)))
                        eleLevList_0.append(tempp_ele)
                        eleLevList_1.append(tempp_ele)
                    else:    
                        eleLevList_0.append((self.ES0[i][0], self.ES0[i][1]))
                        eleLevList_1.append((self.ES1[i][0], self.ES1[i][1]))

                    temp_tag_0 = get_random_bytes(16)
                    temp_tag_1 = byteXor(temp_tag, temp_tag_0)
                    shareLevTagList_0.append(temp_tag_0)
                    shareLevTagList_1.append(temp_tag_1)
                else:
                    tagEllList.append(temp_tag)
                    if temp_tag[:8]==self.dummyT:
                        tempp_ele = (self.dummyE+str(int.from_bytes(temp_tag[8:], 'big',signed=False)),str(random.randint(0,sys.maxsize)),self.ES0[i][2])
                        eleEllList_0.append(tempp_ele)
                        eleEllList_1.append(tempp_ele)
                    else:    
                        eleEllList_0.append(self.ES0[i])
                        eleEllList_1.append(self.ES1[i])

                    temp_tag_0 = get_random_bytes(16)
                    temp_tag_1 = byteXor(temp_tag, temp_tag_0)
                    temp_level_0 = str(random.randint(0,sys.maxsize))
                    temp_level_1 = strXor(temp_level, temp_level_0)
                    shareEllTagList_0.append((temp_tag_0, temp_level_0))
                    shareEllTagList_1.append((temp_tag_1, temp_level_1))

        for i in range(1, len(self.TB0)):
            temp_level = strXor(self.TB0[i][1],self.TB1[i][1])
            if temp_level!="0":
                temp_tag = byteXor(self.TB0[i][0],self.TB1[i][0])
                if int(temp_level)<lev:
                    tagLevList.append(temp_tag)
                    if temp_tag[:8]==self.dummyT:
                        tempp_ele = (self.dummyE+str(int.from_bytes(temp_tag[8:], 'big',signed=False)),str(random.randint(0,sys.maxsize)))
                        eleLevList_0.append(tempp_ele)
                        eleLevList_1.append(tempp_ele)
                    else:    
                        eleLevList_0.append((self.EB0[i][0], self.EB0[i][1]))
                        eleLevList_1.append((self.EB1[i][0], self.EB1[i][1]))

                    temp_tag_0 = get_random_bytes(16)
                    temp_tag_1 = byteXor(temp_tag, temp_tag_0)
                    shareLevTagList_0.append(temp_tag_0)
                    shareLevTagList_1.append(temp_tag_1)
                else:
                    tagEllList.append(temp_tag)
                    if temp_tag[:8]==self.dummyT:
                        tempp_ele = (self.dummyE+str(int.from_bytes(temp_tag[8:], 'big',signed=False)),str(random.randint(0,sys.maxsize)),self.EB0[i][2])
                        eleEllList_0.append(tempp_ele)
                        eleEllList_1.append(tempp_ele)
                    else:    
                        eleEllList_0.append(self.EB0[i])
                        eleEllList_1.append(self.EB1[i])

                    temp_tag_0 = get_random_bytes(16)
                    temp_tag_1 = byteXor(temp_tag, temp_tag_0)
                    temp_level_0 = str(random.randint(0,sys.maxsize))
                    temp_level_1 = strXor(temp_level, temp_level_0)
                    shareEllTagList_0.append((temp_tag_0, temp_level_0))
                    shareEllTagList_1.append((temp_tag_1, temp_level_1))


        for j in range(self.ell+1, lev):
            for i in range(1, len(self.TT0[j-self.ell].table[0])): #+1
                temp_tag = byteXor(self.TT0[j-self.ell].table[0][i],self.TT1[j-self.ell].table[0][i])
                if temp_tag!=bytes(16):
                    tagLevList.append(temp_tag)
                    if temp_tag[:8]==self.dummyT:
                        tempp_ele = (self.dummyE+str(int.from_bytes(temp_tag[8:], 'big',signed=False)),str(random.randint(0,sys.maxsize)))
                        eleLevList_0.append(tempp_ele)
                        eleLevList_1.append(tempp_ele)
                    else:    
                        eleLevList_0.append(self.ET0[j-self.ell].table[0][i])
                        eleLevList_1.append(self.ET1[j-self.ell].table[0][i])

                    temp_tag_0 = get_random_bytes(16)
                    temp_tag_1 = byteXor(temp_tag, temp_tag_0)
                    shareLevTagList_0.append(temp_tag_0)
                    shareLevTagList_1.append(temp_tag_1)
 
                temp_tag = byteXor(self.TT0[j-self.ell].table[1][i],self.TT1[j-self.ell].table[1][i])
                if temp_tag!=bytes(16):
                    tagLevList.append(temp_tag)
                    if temp_tag[:8]==self.dummyT:
                        tempp_ele = (self.dummyE+str(int.from_bytes(temp_tag[8:], 'big',signed=False)),str(random.randint(0,sys.maxsize)))
                        eleLevList_0.append(tempp_ele)
                        eleLevList_1.append(tempp_ele)
                    else:    
                        eleLevList_0.append(self.ET0[j-self.ell].table[1][i])
                        eleLevList_1.append(self.ET1[j-self.ell].table[1][i])

                    temp_tag_0 = get_random_bytes(16)
                    temp_tag_1 = byteXor(temp_tag, temp_tag_0)
                    shareLevTagList_0.append(temp_tag_0)
                    shareLevTagList_1.append(temp_tag_1)

        self.subRebuildFL(tagEllList, eleEllList_0, eleEllList_1, shareEllTagList_0, shareEllTagList_1)
        self.subRebuild(llev, tagLevList, eleLevList_0, eleLevList_1, shareLevTagList_0, shareLevTagList_1)

if __name__=="__main__":
    NN = 2**8
    A = []
    for i in range(NN):
        A.append((str(i), str(i+3))) # random.randint(0,sys.maxsize)
    coram = cORAM(NN, "1O(log N)") #lambda*O(log N)
    coram.initialization(A)
    #print(coram.ET0[coram.L-coram.ell].table[0])
    #print(coram.ET1[coram.L-coram.ell].table[0])
    #print(coram.ET0[coram.L-coram.ell].table[1])
    #print(coram.ET0[coram.L-coram.ell].stash)
    #print(coram.EC0.table[0])
    #print(coram.EC0.table[1])
    #print(coram.ES0)
    OP = ["w","r"]
    access_times = len(A)//2
    pbar = tqdm(total=access_times)
    for i in range(access_times): #NN//2
        index = random.randint(0,5)#random.randint(0,NN-1)
        #print("AinEle:{}".format(A[index]))
        k = A[index][0]
        v = str(random.randint(0,sys.maxsize))
        op = random.choice(OP)
        retrievedEle = coram.access(op, k, v)
        #print(i, retrievedEle)
        # assert (retrievedEle[0], retrievedEle[1])==A[index]
        if (retrievedEle[0], retrievedEle[1])!=A[index]:
            #print()
            print(retrievedEle)
            print(A[index])
        if op == "w":
            A[index]=(k,v)
        #print()
        #print(v)
        pbar.update(math.ceil((i+1)/(access_times)))
    pbar.close()
    print(coram.blockNum)
    print(coram.blockNum/access_times)
    #print(coram.ET0[coram.L-coram.ell].dict[0])
    #print(coram.ET0[coram.L-coram.ell].dict[1])
        





        