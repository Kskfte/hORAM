import client
import math
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import numpy as np
from cuckooHash import CuckooMap
from standardHash import StandardHashwithStash
import copy
from tqdm import tqdm
import tutils
import time
import sys
import pickle

class tORAMClient:
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
        self.N = N
        self.lenStash = math.ceil(math.log2(N))
        self.c = 2*self.lenStash
        self.maxLevel = 1 + math.ceil(math.log2(N/(self.c)))
        self.ellCuckoo = min(self.maxLevel, math.ceil(math.log2(math.log2(self.N))))#math.ceil(math.log2(math.pow(math.log2(N), 6)))) # (int)(7*math.log2(math.log2(N)))
        self.countQ = 0 # count access times
        self.countS = 0 # count dummy elements
        self.full = [0 for i in range(self.maxLevel+1)]

        self.levelMasterKey = get_random_bytes(16)
        self.levelMasterCipher = AES.new(self.levelMasterKey, AES.MODE_ECB, use_aesni=True)
        self.prfSecretkey = get_random_bytes(16)
        self.prfCipher = AES.new(self.prfSecretkey, AES.MODE_ECB, use_aesni=True)

        self.emptyTagKV = (bytes(16),"-1","-1")

        self.dummyTag = bytes(8)
        self.dummyK = "-1"
        self.dummyV = "-1"

        self.availStash = -1

        self.cuckooAlpha = math.ceil(math.log2(self.N))
        self.cuckooEpsilon = 0.01
        
        self.maxLevelCap = (int)((1+self.cuckooEpsilon)*(self.c*2**(self.maxLevel-1)))
        self.emptyForm = (bytes(16),"-1","-1")
        self.eachBucketCapacity = math.ceil(3*math.log2(self.N)/(math.log2(math.log2(self.N))))
        self.threshold_evict = self.cuckooAlpha*math.ceil(math.log2(self.N))

        self.maxLevEpoch = 0


        """
        Evaluation metrics
        """
        self.sendBlockNum = 0
        self.recBlockNum = 0
        self.errorAccess = 0

    def add_to_16(self, value):
        while len(value) % 16 != 0:
            value += '\0'
        return str.encode(value)  # return in bytes    

    def prfTag(self, Cipher, level, epoch, key):
        return Cipher.encrypt(self.add_to_16(str(level)+str(epoch)+str(key)))[:16]
    
    def getEpoch(self, level):
        firstRebuild = math.ceil(math.log2(self.N)*(2**(level-2)))
        if level==self.maxLevel:
            return self.maxLevEpoch
        else:
            return (self.countQ-firstRebuild)//(2*firstRebuild)
    
    def tORAMClientInitialization(self, A): # initialize the array A with the form (k, v)
        """
        Client: generate tag and level hash key. 
        """
        #nowLevelCapacity = math.ceil(self.c*(2**(self.maxLevel-1)))
        
        maxLevelKey = self.prfTag(self.levelMasterCipher,self.maxLevel,0,0)
        self.availStash = 1^(self.maxLevel%2)
        """
        Assume maxLevel is stored in S0, firstly, Send hash key to S1
        """ 
        self.tcpSocList[1^(self.maxLevel%2)].sendMessage(tutils.bytesToStr(maxLevelKey))
        """
        Send data to S1
        """
        for (k,v) in A:
            temp_tag = self.prfTag(self.prfCipher,self.maxLevel,0,k)
            self.tcpSocList[1^(self.maxLevel%2)].sendMessage(tutils.packMToStr((temp_tag,k,v)))  # send (tag, k, v)
        elementNumInStash = int(self.tcpSocList[1^(self.maxLevel%2)].receiveMessage())
        """
        Receive table element and send to S0
        """
        while True:
            mes = self.tcpSocList[1^(self.maxLevel%2)].receiveMessage()
            if mes=="Done":
                break
            (tmp_tag, tmp_k, tmp_v) = tutils.unpackStrToM(mes)
            if (tmp_tag, tmp_k, tmp_v)==self.emptyTagKV and elementNumInStash>0:
                (tmp_tag, tmp_k, tmp_v) = (self.dummyTag+int.to_bytes(self.countS, 8, 'big', signed=False),self.dummyK+str(self.countS),self.dummyV+str(self.countS))
                self.countS += 1
                elementNumInStash -= 1
            self.tcpSocList[(self.maxLevel%2)].sendMessage(tutils.packMToStr((tmp_tag,tmp_k,tmp_v)))
        """
        Stash element then
        """
        while True:
            mes = self.tcpSocList[1^(self.maxLevel%2)].receiveMessage()
            if mes=="Done":
                break
            (tmp_tag, tmp_k, tmp_v) = tutils.unpackStrToM(mes)
            if (tmp_tag, tmp_k, tmp_v)==self.emptyTagKV:
                (tmp_tag, tmp_k, tmp_v) = (self.dummyTag+int.to_bytes(self.countS, 8, 'big', signed=False),self.dummyK+str(self.countS),self.dummyV+str(self.countS))
                self.countS += 1
            self.tcpSocList[(self.maxLevel%2)].sendMessage(tutils.packMToStr((tmp_tag,tmp_k,tmp_v)))

        self.full[self.maxLevel]=1

    def tORAMClientAccess(self, op, k, writeV):
        retrievedEle = (bytes(16),"-1","-1")
        found = False
        foundInWhichStashAndIndex = [-1,-1]
        stashTempIndex = 0
        while True: # S0 first
            mess = self.tcpSoc0.receiveMessage()
            if mess=="Done":
                break
            tempTagKV = tutils.unpackStrToM(mess)
            if tempTagKV[1]==k and not found:
                retrievedEle = tempTagKV
                found = True
                foundInWhichStashAndIndex = [0,stashTempIndex]
            stashTempIndex += 1

            self.recBlockNum += 1
        
        stashTempIndex = 0
        while True: # S1 then
            mess = self.tcpSoc1.receiveMessage()
            if mess=="Done":
                break
            tempTagKV = tutils.unpackStrToM(mess)
            if tempTagKV[1]==k and not found:
                retrievedEle = tempTagKV
                found = True
                foundInWhichStashAndIndex = [1,stashTempIndex]
            stashTempIndex += 1

            self.recBlockNum += 1
        
        for lev in range(2,self.ellCuckoo):
            if self.full[lev]==0:
                continue
            levKey = self.prfTag(self.levelMasterCipher,lev,self.getEpoch(lev),0)
            if found:
                tag = self.prfTag(self.prfCipher,lev,self.getEpoch(lev),(str(-1)+str(self.countQ)))
            else:
                tag = self.prfTag(self.prfCipher,lev,self.getEpoch(lev),k)
            pos = tutils.standardHashPosition(levKey,tag,self.c*(2**(lev-1)))
            self.tcpSocList[lev%2].sendMessage(str(pos))

            self.sendBlockNum += 1

            for _ in range(self.eachBucketCapacity):
                tempTagKV = tutils.unpackStrToM(self.tcpSocList[lev%2].receiveMessage())
                
                if tempTagKV[1]==k and not found:
                    retrievedEle = tempTagKV
                    found = True
                    sendTagKV = (self.dummyTag+int.to_bytes(self.countQ, 8, 'big', signed=False),self.dummyK+str(self.countQ),self.dummyV+str(self.countQ))
                    self.tcpSocList[lev%2].sendMessage(tutils.packMToStr(sendTagKV))
                else:
                    self.tcpSocList[lev%2].sendMessage(tutils.packMToStr(tempTagKV))
                
                self.sendBlockNum += 1
                self.recBlockNum += 1

        
        for lev in range(self.ellCuckoo, self.maxLevel+1):
            if self.full[lev]==0:
                continue
            levKey = self.prfTag(self.levelMasterCipher,lev,self.getEpoch(lev),0)
            if found:
                tag = self.prfTag(self.prfCipher,lev,self.getEpoch(lev),(str(-1)+str(self.countQ)))
            else:
                tag = self.prfTag(self.prfCipher,lev,self.getEpoch(lev),k)
            pos0,pos1 = tutils.cuckooHashPosition(levKey,tag,(int)((1+self.cuckooEpsilon)*self.c*(2**(lev-1))))
            #print((pos0,pos1))
            self.tcpSocList[lev%2].sendMessage(str(pos0)+" "+str(pos1))

            self.sendBlockNum += 1

            tempTagKV0 = tutils.unpackStrToM(self.tcpSocList[lev%2].receiveMessage())
            tempTagKV1 = tutils.unpackStrToM(self.tcpSocList[lev%2].receiveMessage())

            self.recBlockNum += 2

            if tempTagKV0[1]==k and not found:
                retrievedEle = tempTagKV0
                found = True
                sendTagKV0 = (self.dummyTag+int.to_bytes(self.countQ, 8, 'big', signed=False),self.dummyK+str(self.countQ),self.dummyV+str(self.countQ))
                self.tcpSocList[lev%2].sendMessage(tutils.packMToStr(sendTagKV0))
            else:
                self.tcpSocList[lev%2].sendMessage(tutils.packMToStr(tempTagKV0))
    
            if tempTagKV1[1]==k and not found:
                retrievedEle = tempTagKV1
                found = True
                sendTagKV1 = (self.dummyTag+int.to_bytes(self.countQ, 8, 'big', signed=False),self.dummyK+str(self.countQ),self.dummyV+str(self.countQ))
                self.tcpSocList[lev%2].sendMessage(tutils.packMToStr(sendTagKV1))
            else:
                self.tcpSocList[lev%2].sendMessage(tutils.packMToStr(tempTagKV1))
            
            
            self.sendBlockNum += 2

        retrunEle = (retrievedEle[0],retrievedEle[1],retrievedEle[2])
        if op=='w':
            retrievedEle = (retrievedEle[0],retrievedEle[1],writeV)

        stashInd = 0
        while True: # S0 first
            mess = self.tcpSoc0.receiveMessage()
            
            if mess=="Done":
                break
            tempTagKV = tutils.unpackStrToM(mess)
            if foundInWhichStashAndIndex[0]==0 and foundInWhichStashAndIndex[1]==stashInd:
                assert retrunEle==tempTagKV
                self.tcpSoc0.sendMessage(tutils.packMToStr(retrievedEle))
            else:
                self.tcpSoc0.sendMessage(tutils.packMToStr(tempTagKV))
            stashInd += 1

            self.recBlockNum += 1
            self.sendBlockNum += 1
        
        stashInd = 0
        while True: # S1 then
            mess = self.tcpSoc1.receiveMessage()
            if mess=="Done":
                break
            tempTagKV = tutils.unpackStrToM(mess)
            if foundInWhichStashAndIndex[0]==1 and foundInWhichStashAndIndex[1]==stashInd:
                assert retrunEle==tempTagKV
                self.tcpSoc1.sendMessage(tutils.packMToStr(retrievedEle))
            else:
                self.tcpSoc1.sendMessage(tutils.packMToStr(tempTagKV))
            stashInd += 1

            self.recBlockNum += 1
            self.sendBlockNum += 1

        if foundInWhichStashAndIndex[0]==-1:
            self.tcpSocList[self.availStash].sendMessage(tutils.packMToStr(retrievedEle))
        else:
            self.tcpSocList[self.availStash].sendMessage(tutils.packMToStr((self.dummyTag+int.to_bytes(self.countQ, 8, 'big', signed=False),self.dummyK+str(self.countQ),self.dummyV+str(self.countQ))))
        
        self.countQ += 1
        
        self.sendBlockNum += 1

        if self.countQ%self.lenStash==0:
            rebuildL = False
            for i in range(2,self.maxLevel):
                if self.full[i]==0:
                    self.tORAMClientRebuild(i)
                    rebuildL = True
                    break
            if not rebuildL:
                self.tORAMClientRebuildL()

        return retrunEle

    def tORAMClientRebuild(self, rebLev):
        sa = 1^(rebLev%2)
        sb = 1^sa
        while True:
            mess = self.tcpSocList[sa].receiveMessage()
            if mess=="Done":
                self.tcpSocList[sb].sendMessage("Done")
                break
            tagKV = tutils.unpackStrToM(mess)
            self.tcpSocList[sb].sendMessage(tutils.packMToStr(tagKV))
            
            self.sendBlockNum += 1
            self.recBlockNum += 1
        
        
        rebLevKey = self.prfTag(self.levelMasterCipher,rebLev,self.getEpoch(rebLev),0)
        self.tcpSocList[sa].sendMessage(tutils.bytesToStr(rebLevKey))
        
        self.sendBlockNum += 1

        while True:
            mess = self.tcpSocList[sb].receiveMessage()
            if mess=="Done":
                self.tcpSocList[sa].sendMessage("Done")
                break
            tagKV = tutils.unpackStrToM(mess)
            if tagKV==self.emptyTagKV:
                continue
            sendTagKV = (self.prfTag(self.prfCipher,rebLev,self.getEpoch(rebLev),tagKV[1]), tagKV[1], tagKV[2])
            self.tcpSocList[sa].sendMessage(tutils.packMToStr(sendTagKV))
            
            self.sendBlockNum += 1
            self.recBlockNum += 1
        
        elementNumInStash = int(self.tcpSocList[sa].receiveMessage())
        self.recBlockNum += 1
        """
        Receive table element and send to S0
        """
        while True:
            mes = self.tcpSocList[sa].receiveMessage()
            if mes=="Done":
                break
            (tmp_tag, tmp_k, tmp_v) = tutils.unpackStrToM(mes)
            if (tmp_tag, tmp_k, tmp_v)==self.emptyTagKV and elementNumInStash>0:
                (tmp_tag, tmp_k, tmp_v) = (self.dummyTag+int.to_bytes(self.countS, 8, 'big', signed=False),self.dummyK+str(self.countS),self.dummyV+str(self.countS))
                self.countS += 1
                elementNumInStash -= 1
            self.tcpSocList[sb].sendMessage(tutils.packMToStr((tmp_tag,tmp_k,tmp_v)))
            
            self.sendBlockNum += 1
            self.recBlockNum += 1
        """
        Stash element then
        """
        while True:
            mes = self.tcpSocList[sa].receiveMessage()
            if mes=="Done":
                break
            (tmp_tag, tmp_k, tmp_v) = tutils.unpackStrToM(mes)
            if (tmp_tag, tmp_k, tmp_v)==self.emptyTagKV:
                (tmp_tag, tmp_k, tmp_v) = (self.dummyTag+int.to_bytes(self.countS, 8, 'big', signed=False),self.dummyK+str(self.countS),self.dummyV+str(self.countS))
                self.countS += 1
            self.tcpSocList[sb].sendMessage(tutils.packMToStr((tmp_tag,tmp_k,tmp_v)))
            
            self.sendBlockNum += 1
            self.recBlockNum += 1

        for i in range(2,rebLev):
            self.full[i]=0
        self.full[rebLev]=1
        self.availStash=sa
        


    def tORAMClientRebuildL(self):
        """
        Client: generate tag and level hash key. 
        Assume maxLevel is stored in S0, firstly, Send hash key to S1
        """
        maxLevelKey = self.prfTag(self.levelMasterCipher,self.maxLevel,self.maxLevEpoch+1,0)
        self.tcpSocList[1^(self.maxLevel%2)].sendMessage(tutils.bytesToStr(maxLevelKey))
        
        self.sendBlockNum += 1

        for i in range(self.N):
            tagKV = self.tORAMClientReadOnly(str(i+1))
            sendTagKV = (self.prfTag(self.prfCipher,self.maxLevel,self.maxLevEpoch+1,tagKV[1]),tagKV[1],tagKV[2])
            #print(sendTagKV)
            self.tcpSocList[1^(self.maxLevel%2)].sendMessage(tutils.packMToStr(sendTagKV))
            
            self.sendBlockNum += 1

        elementNumInStash = int(self.tcpSocList[1^(self.maxLevel%2)].receiveMessage())
        self.recBlockNum += 1

        """
        Receive table element and send to S0
        """
        while True:
            mes = self.tcpSocList[1^(self.maxLevel%2)].receiveMessage()
            if mes=="Done":
                break
            (tmp_tag, tmp_k, tmp_v) = tutils.unpackStrToM(mes)
            if (tmp_tag, tmp_k, tmp_v)==self.emptyTagKV and elementNumInStash>0:
                (tmp_tag, tmp_k, tmp_v) = (self.dummyTag+int.to_bytes(self.countS, 8, 'big', signed=False),self.dummyK+str(self.countS),self.dummyV+str(self.countS))
                self.countS += 1
                elementNumInStash -= 1
            self.tcpSocList[(self.maxLevel%2)].sendMessage(tutils.packMToStr((tmp_tag,tmp_k,tmp_v)))
            
            self.sendBlockNum += 1
            self.recBlockNum += 1
        """
        Stash element then
        """
        while True:
            mes = self.tcpSocList[1^(self.maxLevel%2)].receiveMessage()
            if mes=="Done":
                break
            (tmp_tag, tmp_k, tmp_v) = tutils.unpackStrToM(mes)
            if (tmp_tag, tmp_k, tmp_v)==self.emptyTagKV:
                (tmp_tag, tmp_k, tmp_v) = (self.dummyTag+int.to_bytes(self.countS, 8, 'big', signed=False),self.dummyK+str(self.countS),self.dummyV+str(self.countS))
                self.countS += 1
            self.tcpSocList[(self.maxLevel%2)].sendMessage(tutils.packMToStr((tmp_tag,tmp_k,tmp_v)))
            
            self.sendBlockNum += 1
            self.recBlockNum += 1

        for i in range(2,self.maxLevel):
            self.full[i]=0
        self.full[self.maxLevel]=1
        self.availStash = 1^(self.maxLevel%2)
        self.maxLevEpoch += 1

    def tORAMClientReadOnly(self,k):
        retrievedEle = (bytes(16),"-1","-1")
        found = False
        while True: # S0 first
            mess = self.tcpSoc0.receiveMessage()
            if mess=="Done":
                break
            tempTagKV = tutils.unpackStrToM(mess)
            if tempTagKV[1]==k and not found:
                retrievedEle = tempTagKV
                found = True

            self.recBlockNum += 1
        
        while True:
            mess = self.tcpSoc1.receiveMessage()
            if mess=="Done":
                break
            tempTagKV = tutils.unpackStrToM(mess)
            if tempTagKV[1]==k and not found:
                retrievedEle = tempTagKV
                found = True

            self.recBlockNum += 1
        
        for lev in range(2,self.ellCuckoo):
            if self.full[lev]==0:
                continue
            levKey = self.prfTag(self.levelMasterCipher,lev,self.getEpoch(lev),0)
            if found:
                tag = self.prfTag(self.prfCipher,lev,self.getEpoch(lev),(str(-1)+str(self.countQ)))
            else:
                tag = self.prfTag(self.prfCipher,lev,self.getEpoch(lev),k)
            pos = tutils.standardHashPosition(levKey,tag,self.c*(2**(lev-1)))
            self.tcpSocList[lev%2].sendMessage(str(pos))
            
            self.sendBlockNum += 1

            for _ in range(self.eachBucketCapacity):
                tempTagKV = tutils.unpackStrToM(self.tcpSocList[lev%2].receiveMessage())

                self.recBlockNum += 1

                if tempTagKV[1]==k and not found:
                    retrievedEle = tempTagKV
                    found = True
        
        for lev in range(self.ellCuckoo, self.maxLevel+1):
            if self.full[lev]==0:
                continue
            levKey = self.prfTag(self.levelMasterCipher,lev,self.getEpoch(lev),0)
            if found:
                tag = self.prfTag(self.prfCipher,lev,self.getEpoch(lev),(str(-1)+str(self.countQ)))
            else:
                tag = self.prfTag(self.prfCipher,lev,self.getEpoch(lev),k)
            pos0,pos1 = tutils.cuckooHashPosition(levKey,tag,(int)((1+self.cuckooEpsilon)*self.c*(2**(lev-1))))
            self.tcpSocList[lev%2].sendMessage(str(pos0)+" "+str(pos1))
            
            self.sendBlockNum += 1

            tempTagKV0 = tutils.unpackStrToM(self.tcpSocList[lev%2].receiveMessage())
            tempTagKV1 = tutils.unpackStrToM(self.tcpSocList[lev%2].receiveMessage())

            self.recBlockNum += 2

            if tempTagKV0[1]==k and not found:
                retrievedEle = tempTagKV0
                found = True         
            if tempTagKV1[1]==k and not found:
                retrievedEle = tempTagKV1
                found = True

        return retrievedEle

        
        
                


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
    
    coram = tORAMClient(NN)
    coram.tORAMClientInitialization(A)
    
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
        retrievedEle = coram.tORAMClientAccess(op, k, v)
        #print(retrievedEle)
        #print(A[index])
        #print(retrievedEle)
        #assert (retrievedEle[0], retrievedEle[1])==A[index]
        if not (retrievedEle[1], retrievedEle[2])==A[index]:
            error_times += 1
        #print((i,error_times))
        if op == "w":
            A[index]=(k,v)
        #print(A[index]) 

        
        sendBlockList.append(coram.sendBlockNum)
        recBlockList.append(coram.recBlockNum)
        accessTimesList.append(i+1)
        consumeTimeList.append(time.time()-bb)
        clientPermStoList.append(1)
        clientAccessStoList.append(1)

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
    pic = open(r'C:\Users\zxl\Desktop\LORAM\GitRespositery\hORAM\Result\LO13BlockNum_{}.pkl'.format(NN), 'wb')#open(r'.\Result\BlockNum_{}.pkl'.format(NN), 'wb')
    pickle.dump(data,pic)
    pic.close()