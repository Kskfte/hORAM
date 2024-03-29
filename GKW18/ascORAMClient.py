import math
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import numpy as np
import copy
import sys
from tqdm import tqdm
import time
import client
import pickle
import gutils
#from utils import byteXor, strXor, bytesToStr, strToBytes
class aORAMClient:
    """
    we assume the server stores (tag, (k,v))
    tag = k for dummy elements
    """

    def __init__(self, N) -> None: #, c, ellCuckoo, countQ, countS, maxLevel all+1 dORAM.OldEmpty
        """
        Initialize the tcp Comm
        """
        self.byteOfComm = 1024
        self.tcpSoc0 = client.tcpClient(client.Addr0,client.Port0,self.byteOfComm)
        self.tcpSoc1 = client.tcpClient(client.Addr1,client.Port1,self.byteOfComm)
        self.tcpSoc0.sendMessage(str(N))
        self.tcpSoc1.sendMessage(str(N))
        self.tcpSocList = [self.tcpSoc0, self.tcpSoc1]

        """
        Initialize the parameters
        """
        self.emptyForm = ("-1","-1")
        self.N = N
        self.A = 1
        self.Z = 2
        self.ctr = -1
        self.treeDepth = math.ceil(math.log2(self.N)) # 1,2,...,treedepth
        self.leafNum = self.N

        self.masterKey = get_random_bytes(16)
        self.masterCipher = AES.new(self.masterKey, AES.MODE_ECB, use_aesni=True)

        self.localStorage = []

        """
        Metrics
        """
        self.sendBlockNum = 0
        self.recBlockNum = 0
        self.clientPermStorage = 0
        self.clientAcessStorage = 0

    def add_to_16(self, value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)  # return in bytes    

    def prfTag(self, Cipher, key):
        return Cipher.encrypt(self.add_to_16(str(key)))[:16]
    
    def hashPosition(self, tag):
        """
        Ensure the position 0 does not store elements
        """
        secretkey0 = self.masterCipher.encrypt(self.add_to_16(str(0)))
        return hash(str(tag)+str(secretkey0)) % self.leafNum
    
    def aORAMClientInitialization(self, arrayA):
        for (k,v) in arrayA:
            leafPos = self.hashPosition(self.prfTag(self.masterCipher,k))
            self.tcpSoc0.sendMessage(gutils.packKVPosToStr((k,v,leafPos)))
            self.tcpSoc1.sendMessage(gutils.packKVPosToStr((k,v,leafPos)))

        while True:
            mess = self.tcpSoc0.receiveMessage()
            if mess=="Done":
                break
            self.localStorage.append(gutils.unpackStrToKV(mess))
    
    def aORAMClientAccess(self, op, queryK, writeV):
        found = False
        retrievedEle = ("-1","-1")
        for i in range(len(self.localStorage)):
            if self.localStorage[i][0]==queryK and not found:
                retrievedEle=self.localStorage[i]
                found = True
                break
        if found:
            self.localStorage.remove(retrievedEle)

        leafPos = self.hashPosition(self.prfTag(self.masterCipher,queryK))
        pk,ck,k0,k1 = gutils.dpfGenKeys(leafPos, self.leafNum)

        self.tcpSoc0.sendMessage(gutils.dpfKeysToStr((pk,ck,k0)))
        self.tcpSoc1.sendMessage(gutils.dpfKeysToStr((pk,ck,k1)))

        self.sendBlockNum += 2

        for _ in range(self.treeDepth):
            for _ in range(self.Z):
                (accessK0,accessV0) = gutils.unpackStrToKV(self.tcpSoc0.receiveMessage())
                (accessK1,accessV1) = gutils.unpackStrToKV(self.tcpSoc1.receiveMessage())
                self.recBlockNum += 2
                (recK, recV) = (gutils.strXor(accessK0,accessK1),gutils.strXor(accessV0,accessV1))
                if recK==queryK and not found:
                    retrievedEle=(recK, recV)
                    found = True

        returnEle = (retrievedEle[0],retrievedEle[1])
        if op=='w':
            retrievedEle = (retrievedEle[0],writeV)
        self.localStorage.append(retrievedEle)
        self.ctr = (self.ctr+1)%self.leafNum
        if self.ctr%self.A==0:
            self.aORAMClientEvict()

        self.clientPermStorage = len(self.localStorage)

        return returnEle

    def aORAMClientEvict(self):
        leafPos = gutils.reverseBit(self.ctr,self.treeDepth)
        for i in range(1,self.treeDepth+1):
            for j in range(self.Z):
                recKV = gutils.unpackStrToKV(self.tcpSoc0.receiveMessage())
                self.recBlockNum += 1
                if recKV!=self.emptyForm and not gutils.whetherKVInStash(recKV,self.localStorage):
                    self.localStorage.append(recKV)
        
        random.shuffle(self.localStorage)
        tempPos = []
        for (k,_) in self.localStorage:
            loc = self.hashPosition(self.prfTag(self.masterCipher,k))
            tempPos.append(loc)


        tempBuildPath = [[self.emptyForm for _ in range(self.Z)] for _ in range(self.treeDepth)]
        

        haveWriteDict = {}
        for i in range(len(self.localStorage)):
            kV = self.localStorage[i]
            tmpLev = gutils.findSharedLevel(tempPos[i],leafPos,self.treeDepth)
            #if tmpLev<1:
            #    continue
            for wLev in range(tmpLev-1,-1,-1):
                if self.emptyForm in tempBuildPath[wLev]:
                    tmpInd = tempBuildPath[wLev].index(self.emptyForm)
                    tempBuildPath[wLev][tmpInd] = kV
                    haveWriteDict[kV[0]]=kV[1]
                    break

        for kVList in tempBuildPath:
            for kV in kVList:
                self.tcpSoc0.sendMessage(gutils.packKVToStr(kV))
                self.tcpSoc1.sendMessage(gutils.packKVToStr(kV))
                self.sendBlockNum += 2

        for k in haveWriteDict.keys():        
            self.localStorage.remove((k,haveWriteDict[k]))
        
        self.clientAcessStorage = len(self.localStorage)+self.Z*self.treeDepth
        

if __name__=="__main__":
    NN = 2**12
    A = []
    for i in range(NN):
        A.append((str(i+1), str(i+3))) 
    
    sendBlockList = []
    recBlockList = []
    accessTimesList = []
    consumeTimeList = []
    clientPermStoList = []
    clientAccessStoList = []
    
    coram = aORAMClient(NN)
    coram.aORAMClientInitialization(A)
    
    OP = ["w", "r"]
    access_times = 4*NN-1#1#len(A)//2 513#
    error_times = 0
    pbar = tqdm(total=access_times)
    bb = time.time()
    for i in range(access_times):
        index = random.randint(0,len(A)-1)#random.randint(0,1)#random.randint(0,1)#random.randint(0,len(A)-1)
        k = A[index][0]
        v = str(random.randint(0,sys.maxsize))
        op = random.choice(OP)
        retrievedEle = coram.aORAMClientAccess(op, k, v)
        #print(retrievedEle)
        #print(A[index])
        #print(retrievedEle)
        #assert (retrievedEle[0], retrievedEle[1])==A[index]
        if not (retrievedEle[0], retrievedEle[1])==A[index]:
            error_times += 1
        #print((i,error_times))
        if op == "w":
            A[index]=(k,v)
        #print(A[index]) 

        
        sendBlockList.append(coram.sendBlockNum)
        recBlockList.append(coram.recBlockNum)
        accessTimesList.append(i+1)
        consumeTimeList.append(time.time()-bb)
        clientPermStoList.append(coram.clientPermStorage+1)
        clientAccessStoList.append(coram.clientAcessStorage+1)

        pbar.update(math.ceil((i+1)/(access_times)))
    ee = time.time()
    pbar.close()

    print(ee-bb)
    print(error_times)
    print(coram.sendBlockNum)
    print(coram.recBlockNum)
    print(coram.sendBlockNum+coram.recBlockNum)
    print(coram.sendBlockNum/access_times)
    print(coram.recBlockNum/access_times)
    print((coram.sendBlockNum+coram.recBlockNum)/access_times)
    coram.tcpSoc0.closeConnection()
    coram.tcpSoc1.closeConnection()

    data = {'SendBlock':sendBlockList,'RecBlock':recBlockList,'AccessTimes':accessTimesList,'ConsumeTime':consumeTimeList,'ClientPermSto':clientPermStoList,'ClientAccessSto':clientAccessStoList}
    pic = open(r'C:\Users\zxl\Desktop\LORAM\GitRespositery\hORAM\Result\GKW18BlockNum_{}.pkl'.format(NN), 'wb')
    pickle.dump(data,pic)
    pic.close()





            


