import math
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import numpy as np
from cuckooHashOneOffet import CuckooMap
import copy
import sys
from pir import PIRRead,PIRWrite
from dpfLog import logDPF
from tqdm import tqdm
import time
import client
import cutils
import pickle
#from utils import byteXor, strXor, bytesToStr, strToBytes

"""
tcp: 粘包
udp: 无序+丢包
"""

class ORAMClient:
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
        self.ecEllLength = 2**(self.ell+1)+math.ceil(math.log2(N))*(self.L-self.ell)
        self.ctr = 0
        self.full = [0 for i in range(self.L-self.ell+1)] # 1,2,...
        self.eleEmptyForm = ("-1","-1")
        self.tagEmptyForm = bytes(16)
        tmp_val = 1
        self.dummyT = tmp_val.to_bytes(8,'big')
        self.dummyE = str(sys.maxsize)
        self.ellEpoch = 0
        self.Lepoch = 0
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

        self.cuckooAlpha = math.ceil(math.log2(N))
        self.cuckooEpsilon = 0.01

        
        self.ellTableLength = (int)((1+self.cuckooEpsilon)*self.ecEllLength)

        """
        Evaluation metrics
        """
        self.sendBlockNum = 0
        self.recBlockNum = 0
        self.errorAccess = 0
        self.byteOfCom = 1024

        """

        """
        self.lenEBAndTB = 0
        self.lenES = 0
        self.tcpSoc0 = client.tcpClient(client.Addr0, client.Port0, self.byteOfCom)
        self.tcpSoc1 = client.tcpClient(client.Addr1, client.Port1, self.byteOfCom)
        self.tcpSoc0.sendMessage(str(self.N))
        self.tcpSoc1.sendMessage(str(self.N))
    
    def receiveMAndSplit(self, soc):
        return soc.receiveMessage().split( )
        
    def receiveM(self, soc):
        return soc.receiveMessage()
            
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
            return self.Lepoch#self.ctr//(2**level)
        else:
            #assert self.ctr>=2**level
            return max(0, (self.ctr-2**level))//(2*(2**level))
    
    def secretShareTag(self, tag):
        tag_0 = get_random_bytes(16)
        tag_1 = cutils.byteXor(tag, tag_0)
        return tag_0, tag_1
    
    def secretShareLevel(self, levelStr):
        level_0 = str(random.randint(0,sys.maxsize))
        level_1 = cutils.strXor(levelStr, level_0)
        return level_0, level_1

    def hashPosition(self, levelCipher, tag, tableLength):
        """
        Ensure the position 0 does not store elements
        """
        secretkey0 = levelCipher.encrypt(self.add_to_16(str(0)))#get_random_bytes(16)
        secretkey1 = levelCipher.encrypt(self.add_to_16(str(1)))#get_random_bytes(16)
        return hash(str(secretkey0)+str(tag)) % (tableLength-1) + 1, hash(str(secretkey1)+str(tag)) % (tableLength-1) + 1

    def oramClientInitialization(self, A):
        LLevelCipher = self.generateLevelCipher(self.L, 0)
        ellLevelCipher = self.generateLevelCipher(self.ell, 0)
        for (k,v) in A:
            levTableLength = (int)((1+self.cuckooEpsilon)*(2**self.L))
            tag = self.generateTag(k)
            shareTag0, shareTag1 = self.secretShareTag(tag)
            posNowLevel0,posNowLevel1 = self.hashPosition(LLevelCipher, tag, levTableLength)
            posEllLevel0,posEllLevel1 = self.hashPosition(ellLevelCipher, tag, self.ellTableLength)

            dataMessage0 = k+" "+v+" "+cutils.bytesToStr(shareTag0)+" "+str(posNowLevel0)+" "+str(posNowLevel1)+" "+str(posEllLevel0)+" "+str(posEllLevel1)+"\n"
            dataMessage1 = k+" "+v+" "+cutils.bytesToStr(shareTag1)+" "+str(posNowLevel0)+" "+str(posNowLevel1)+" "+str(posEllLevel0)+" "+str(posEllLevel1)+"\n"
   
            """
            send to server
            """
            self.tcpSoc0.sendMessage(dataMessage0)
            self.tcpSoc1.sendMessage(dataMessage1)

        tmpData = self.receiveMAndSplit(self.tcpSoc0)
        self.lenES = int(tmpData[0])
        self.lenEBAndTB = int(tmpData[1])
        self.full[0] = int(tmpData[2])
        self.full[self.L-self.ell]=1
             
    def oramClientAccess(self, op, a, writeV):
        found = False
        tag = self.generateTag(a)
        retrievedEle = ("-1","-1")                    
        writeModTag = (cutils.byteXor(tag, self.dummyT+self.ctr.to_bytes(8,'big')))

        if self.lenEBAndTB>1:
            tempBPos = 0
            for i in range(self.lenEBAndTB-1, 0, -1):
                recK,recV = self.receiveMAndSplit(self.tcpSoc0)
                
                self.recBlockNum += 1

                if (not found) and recK==a:
                    retrievedEle = (recK, recV)
                    tempBPos = i
                    found = True

            prfK, convertK, k_0, k_1 = cutils.dpfGenKeys(tempBPos, self.lenEBAndTB)
            self.tcpSoc0.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_0)))
            self.tcpSoc1.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_1)))

            self.sendBlockNum += 4

        if self.lenES>1:
            tempEPos = 0
            for i in range(1, self.lenES):
                recK,recV = self.receiveMAndSplit(self.tcpSoc0)

                self.recBlockNum += 1

                if (not found) and recK==a:
                    retrievedEle = (recK, recV)
                    tempEPos = i
                    found = True

            prfK, convertK, k_0, k_1 = cutils.dpfGenKeys(tempEPos, self.lenES)
            self.tcpSoc0.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_0)))
            self.tcpSoc1.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_1)))
            
            self.sendBlockNum += 4
            

        if self.full[0]==1:
            ellLevelCipher = self.generateLevelCipher(self.ell, self.getEpoch(self.ell))
            pos_0, pos_1 = self.hashPosition(ellLevelCipher, tag, self.ellTableLength)
            T0prfK, T0convertK, T0k_0, T0k_1 = cutils.dpfGenKeys(pos_0, self.ellTableLength)
            T1prfK, T1convertK, T1k_0, T1k_1 = cutils.dpfGenKeys(pos_1, self.ellTableLength)
            
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_0)))
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_0)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_1)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_1)))
            
            self.sendBlockNum += 4
        
        for lev in range(self.ell+1,self.L+1):
            if self.full[lev-self.ell]==0:
                continue
            levelCipher = self.generateLevelCipher(lev, self.getEpoch(lev))
            levTableLength = (int)((1+self.cuckooEpsilon)*(2**lev))
            pos_0, pos_1 = self.hashPosition(levelCipher, tag, levTableLength)#ET0[lev-self.ell].getPos(levelCipher, tag)

            T0prfK, T0convertK, T0k_0, T0k_1 = cutils.dpfGenKeys(pos_0, levTableLength)
            T1prfK, T1convertK, T1k_0, T1k_1 = cutils.dpfGenKeys(pos_1, levTableLength)
    
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_0)))
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_0)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_1)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_1)))
            
            self.sendBlockNum += 4

        if self.full[0]==1:
            ellLevelCipher = self.generateLevelCipher(self.ell, self.getEpoch(self.ell))
            pos_0, pos_1 = self.hashPosition(ellLevelCipher, tag, self.ellTableLength)
            
            temp_share_data_0 = self.receiveMAndSplit(self.tcpSoc0)#temp_d0.split( )
            temp_share_data_1 = self.receiveMAndSplit(self.tcpSoc0)# temp_d1.split( )
            temp_share_data_01 = self.receiveMAndSplit(self.tcpSoc1)# temp_d01.split( )
            temp_share_data_11 = self.receiveMAndSplit(self.tcpSoc1)# temp_d11.split( )

            self.recBlockNum += 4
            temp_data_0 = (cutils.strXor(temp_share_data_0[0],temp_share_data_01[0]),cutils.strXor(temp_share_data_0[1],temp_share_data_01[1]))
            temp_data_1 = (cutils.strXor(temp_share_data_1[0],temp_share_data_11[0]),cutils.strXor(temp_share_data_1[1],temp_share_data_11[1]))

            if (not found) and temp_data_0[0]==a:# and temp_data_0[1]!='0':
                retrievedEle = temp_data_0
                found = True
                
                prfK, convertK, k_0, k_1 = cutils.dpfGenKeys(pos_0, self.ellTableLength)
                self.tcpSoc0.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
                self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_0)))
                self.tcpSoc1.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
                self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_1)))

            else:
                prfK, convertK, k_0, k_1 = cutils.dpfGenKeys(0, self.ellTableLength)
                self.tcpSoc0.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
                self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_0)))
                self.tcpSoc1.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
                self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_1)))

                
            if (not found) and temp_data_1[0]==a:# and temp_data_1[1]!='0':
                retrievedEle = temp_data_1
                found = True

                prfK, convertK, k_0, k_1 = cutils.dpfGenKeys(pos_1, self.ellTableLength)
                self.tcpSoc0.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
                self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_0)))
                self.tcpSoc1.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
                self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_1)))

                #PIRWrite(self.TC0.table[0],self.TC1.table[0],2).writeWithPos(pos_0,(tag,retrievedEle[2]),(self.dummyT+self.ctr.to_bytes(8,'big'),retrievedEle[2]), self.TC0.dict[0])
            else:
                prfK, convertK, k_0, k_1 = cutils.dpfGenKeys(0, self.ellTableLength)
                self.tcpSoc0.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
                self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_0)))
                self.tcpSoc1.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
                self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_1)))
            
            self.sendBlockNum += 8    
        
        for lev in range(self.ell+1,self.L+1):
            if self.full[lev-self.ell]==0:
                continue
            levelCipher = self.generateLevelCipher(lev, self.getEpoch(lev))
            levTableLength = (int)((1+self.cuckooEpsilon)*(2**lev))
            pos_0, pos_1 = self.hashPosition(levelCipher, tag, levTableLength)#ET0[lev-self.ell].getPos(levelCipher, tag)
        
            temp_share_data_0 = self.receiveMAndSplit(self.tcpSoc0)#temp_d0.split( )
            temp_share_data_1 = self.receiveMAndSplit(self.tcpSoc0)# temp_d1.split( )
            temp_share_data_01 = self.receiveMAndSplit(self.tcpSoc1)# temp_d01.split( )
            temp_share_data_11 = self.receiveMAndSplit(self.tcpSoc1)# temp_d11.split( )

            self.recBlockNum += 4

            temp_data_0 = (cutils.strXor(temp_share_data_0[0],temp_share_data_01[0]),cutils.strXor(temp_share_data_0[1],temp_share_data_01[1]))
            temp_data_1 = (cutils.strXor(temp_share_data_1[0],temp_share_data_11[0]),cutils.strXor(temp_share_data_1[1],temp_share_data_11[1]))
            
            if (not found) and temp_data_0[0]==a:# and temp_data_0[1]!='0':
                retrievedEle = (temp_data_0[0],temp_data_0[1])
                found = True

                prfK, convertK, k_0, k_1 = cutils.dpfGenKeys(pos_0, levTableLength)
                self.tcpSoc0.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
                self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_0)))
                self.tcpSoc1.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
                self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_1)))
            
                #PIRWrite(self.TC0.table[0],self.TC1.table[0],2).writeWithPos(pos_0,(tag,retrievedEle[2]),(self.dummyT+self.ctr.to_bytes(8,'big'),retrievedEle[2]), self.TC0.dict[0])
            else:
                prfK, convertK, k_0, k_1 = cutils.dpfGenKeys(0, levTableLength)
                self.tcpSoc0.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
                self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_0)))
                self.tcpSoc1.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
                self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_1)))
            
            
            if (not found) and temp_data_1[0]==a:# and temp_data_1[1]!='0':
                retrievedEle = (temp_data_1[0],temp_data_1[1])
                found = True
                
                prfK, convertK, k_0, k_1 = cutils.dpfGenKeys(pos_1, levTableLength)
                self.tcpSoc0.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
                self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_0)))
                self.tcpSoc1.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
                self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_1)))
            
                #PIRWrite(self.TC0.table[0],self.TC1.table[0],2).writeWithPos(pos_0,(tag,retrievedEle[2]),(self.dummyT+self.ctr.to_bytes(8,'big'),retrievedEle[2]), self.TC0.dict[0])
            else:
                prfK, convertK, k_0, k_1 = cutils.dpfGenKeys(0, levTableLength)
                self.tcpSoc0.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
                self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_0)))
                self.tcpSoc1.sendMessage(cutils.pirWriteVToStrEll(writeModTag))
                self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((prfK, convertK, k_1)))

                
            self.sendBlockNum += 8
            
        returnEle = (retrievedEle[0], retrievedEle[1])
        retrievedEle = (retrievedEle[0], retrievedEle[1])
        if op == "w":
            retrievedEle = (retrievedEle[0], writeV)

        tag_0 = get_random_bytes(16)
        tag_1 = cutils.byteXor(tag, tag_0)
        self.tcpSoc0.sendMessage(retrievedEle[0]+" "+retrievedEle[1])
        self.tcpSoc0.sendMessage(cutils.bytesToStr(tag_0))
        
        self.tcpSoc1.sendMessage(retrievedEle[0]+" "+retrievedEle[1])
        self.tcpSoc1.sendMessage(cutils.bytesToStr(tag_1))

        
        self.sendBlockNum += 4

        self.ctr += 1
        self.ellAccessTimes += 1
        self.lenEBAndTB += 1
        
        if self.ctr%(2**self.L)==0:
            self.oramClientRebuildL()
        elif self.ctr%(2**(self.ell+1)) == 0:
            for j in range(self.ell+1, self.L):
                if self.full[j-self.ell]==0:
                    print("ctr:{}".format(self.ctr))
                    print("rebuildLevel:{}".format(j))
                    self.oramClientRebuild(j)
                    self.full[j-self.ell]=1
                    break

        elif self.ellAccessTimes % math.ceil(math.log2(self.N)) == 0:
            self.oramClientRebuildFL()
        
        return returnEle
    
    def oramClientRebuildFL(self):
        self.ellEpoch += 1
        newEllLevCipher = self.generateLevelCipher(self.ell, self.getEpoch(self.ell))
        while True:
            tes = self.receiveMAndSplit(self.tcpSoc0)#self.tcpSoc0.receiveMessage()

            self.recBlockNum += 1
            
            #tes = recEleStr.split( )
            if tes[0] == "Done":
                self.lenES=int(tes[1])
                self.lenEBAndTB=1
                self.full[0]=1
                break
            recTagStr0 = self.receiveM(self.tcpSoc0)#self.tcpSoc0.receiveMessage()   
            recTagStr1 = self.receiveM(self.tcpSoc1)#self.tcpSoc1.receiveMessage()

            self.recBlockNum += 2
            #ele1, _ = self.tcpSoc0.receiveMessage()
            (recK,recV) = tes#recEleStr.split( )
            tmpTag0 = cutils.pirstrToVEll(recTagStr0)
            tmpTag1 = cutils.pirstrToVEll(recTagStr1)
            tag = cutils.byteXor(tmpTag0,tmpTag1)

            if tag[:8]==self.dummyT:
                (recK,recV) = (self.dummyE+str(int.from_bytes(tag[8:], 'big',signed=False)),str(random.randint(0,sys.maxsize)))                     
            (posEllLevel0,posEllLevel1) = self.hashPosition(newEllLevCipher, tag, self.ellTableLength)
            #posEllLevel1 = self.hashPosition(ellSecretkey1, tag, self.ecEllLength)

            dataMessage0 = recK+" "+recV+" "+str(posEllLevel0)+" "+str(posEllLevel1)+"\n"
            dataMessage1 = recK+" "+recV+" "+str(posEllLevel0)+" "+str(posEllLevel1)+"\n"
            #tptp = dataMessage0.split( )
            """
            send to server
            """
            self.tcpSoc0.sendMessage(dataMessage0)
            self.tcpSoc1.sendMessage(dataMessage1)

            self.sendBlockNum += 2
        self.full[0] = 1
        self.ellAccessTimes = 0

    def oramClientRebuild(self, lev):
        self.ellEpoch += 1
        newLevCipher = self.generateLevelCipher(lev, self.getEpoch(lev))
        newEllCipher = self.generateLevelCipher(self.ell, self.getEpoch(self.ell))
        while True:
            tes =  self.receiveMAndSplit(self.tcpSoc0)#recEleStr.split( )

            self.recBlockNum += 1

            if tes[0] == "Done":
                self.lenES=int(tes[1])
                self.lenEBAndTB=1
                self.full[0]=int(tes[2])
                break
            recTagStr0 = self.receiveM(self.tcpSoc0)#self.tcpSoc0.receiveMessage()   
            recTagStr1 = self.receiveM(self.tcpSoc1)#self.tcpSoc1.receiveMessage()

            self.recBlockNum += 2

            (recK,recV) = tes
            tmpTag0 = cutils.pirstrToVEll(recTagStr0)
            tmpTag1 = cutils.pirstrToVEll(recTagStr1)
            tag = cutils.byteXor(tmpTag0,tmpTag1)
            if tag[:8]==self.dummyT:
                (recK,recV) = (self.dummyE+str(int.from_bytes(tag[8:], 'big',signed=False)),str(random.randint(0,sys.maxsize)))                     
            (posLev0,posLev1) = self.hashPosition(newLevCipher,tag,(int)((1+self.cuckooEpsilon)*(2**lev)))
            (posEll0,posEll1) = self.hashPosition(newEllCipher, tag, self.ellTableLength)

            dataMessage0 = recK+" "+recV+" "+str(posLev0)+" "+str(posLev1)+" "+str(posEll0)+" "+str(posEll1)+"\n"
            dataMessage1 = recK+" "+recV+" "+str(posLev0)+" "+str(posLev1)+" "+str(posEll0)+" "+str(posEll1)+"\n"
            
            """
            send to server
            """
            self.tcpSoc0.sendMessage(dataMessage0)
            self.tcpSoc1.sendMessage(dataMessage1)

            self.sendBlockNum += 2
        for j in range(self.ell+1,lev):
            self.full[j-self.ell]=0
        self.full[lev-self.ell] = 1
        self.ellAccessTimes = 0

    def oramClientRebuildL(self):
        newLLevelCipher = self.generateLevelCipher(self.L, self.Lepoch+1)
        newEllLevelCipher = self.generateLevelCipher(self.ell, self.ellEpoch+1)
        levTableLength = (int)((1+self.cuckooEpsilon)*(2**self.L))
        for i in range(self.N):
            (k,v) = self.oramClientOnlyRead(str(i+1))
            tag = self.generateTag(k)
            shareTag0, shareTag1 = self.secretShareTag(tag)
            posNowLevel0,posNowLevel1 = self.hashPosition(newLLevelCipher, tag, levTableLength)
            posEllLevel0,posEllLevel1 = self.hashPosition(newEllLevelCipher, tag, self.ellTableLength)

            dataMessage0 = k+" "+v+" "+cutils.bytesToStr(shareTag0)+" "+str(posNowLevel0)+" "+str(posNowLevel1)+" "+str(posEllLevel0)+" "+str(posEllLevel1)+"\n"
            dataMessage1 = k+" "+v+" "+cutils.bytesToStr(shareTag1)+" "+str(posNowLevel0)+" "+str(posNowLevel1)+" "+str(posEllLevel0)+" "+str(posEllLevel1)+"\n"

            """
            send to server
            """
            self.tcpSoc0.sendMessage(dataMessage0)
            self.tcpSoc1.sendMessage(dataMessage1)

            self.sendBlockNum += 2
        
        self.ellEpoch += 1
        self.Lepoch += 1
        self.full = [0 for i in range(self.L-self.ell+1)]

        tmpData = self.receiveMAndSplit(self.tcpSoc0)
        self.recBlockNum += 1
        self.lenES = int(tmpData[0])
        self.lenEBAndTB = 1
        self.full[0] = int(tmpData[1])
        self.full[self.L-self.ell]=1
        self.ellAccessTimes = 0

    def oramClientOnlyRead(self, a):
        found = False
        tag = self.generateTag(a)
        retrievedEle = ("-1","-1")

        if self.lenEBAndTB>1:
            for i in range(self.lenEBAndTB-1, 0, -1):
                recK, recV =  self.receiveMAndSplit(self.tcpSoc0)
                self.recBlockNum += 1
                if (not found) and recK==a:
                    retrievedEle = (recK, recV)
                    found = True

        if self.lenES>1:
            for i in range(1, self.lenES):
                recK, recV = self.receiveMAndSplit(self.tcpSoc0)
                self.recBlockNum += 1
                if (not found) and recK==a:
                    retrievedEle = (recK, recV)
                    found = True

        if self.full[0]==1:
            ellLevelCipher = self.generateLevelCipher(self.ell, self.getEpoch(self.ell))
            pos_0, pos_1 = self.hashPosition(ellLevelCipher, tag, self.ellTableLength)
            T0prfK, T0convertK, T0k_0, T0k_1 = cutils.dpfGenKeys(pos_0, self.ellTableLength)
            T1prfK, T1convertK, T1k_0, T1k_1 = cutils.dpfGenKeys(pos_1, self.ellTableLength)
            
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_0)))
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_0)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_1)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_1)))
            
            self.sendBlockNum += 4

        for lev in range(self.ell+1,self.L+1):
            assert self.full[lev-self.ell]==1
            levelCipher = self.generateLevelCipher(lev, self.getEpoch(lev))
            levTableLength = (int)((1+self.cuckooEpsilon)*(2**lev))
            pos_0, pos_1 = self.hashPosition(levelCipher, tag, levTableLength)
            T0prfK, T0convertK, T0k_0, T0k_1 = cutils.dpfGenKeys(pos_0, levTableLength)
            T1prfK, T1convertK, T1k_0, T1k_1 = cutils.dpfGenKeys(pos_1, levTableLength)
    
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_0)))
            self.tcpSoc0.sendMessage(cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_0)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((T0prfK, T0convertK, T0k_1)))
            self.tcpSoc1.sendMessage(cutils.dpfKeysToStr((T1prfK, T1convertK, T1k_1)))

            self.sendBlockNum += 4

        if self.full[0]==1:
            temp_share_data_0 = self.receiveMAndSplit(self.tcpSoc0)
            temp_share_data_1 = self.receiveMAndSplit(self.tcpSoc0)
            temp_share_data_01 = self.receiveMAndSplit(self.tcpSoc1)
            temp_share_data_11 = self.receiveMAndSplit(self.tcpSoc1)

            self.recBlockNum += 4

            temp_data_0 = (cutils.strXor(temp_share_data_0[0],temp_share_data_01[0]),cutils.strXor(temp_share_data_0[1],temp_share_data_01[1]))
            temp_data_1 = (cutils.strXor(temp_share_data_1[0],temp_share_data_11[0]),cutils.strXor(temp_share_data_1[1],temp_share_data_11[1]))
            
            if (not found) and temp_data_0[0]==a:# and temp_data_0[1]!='0':
                retrievedEle = temp_data_0
                found = True
            if (not found) and temp_data_1[0]==a:# and temp_data_1[1]!='0':
                retrievedEle = temp_data_1
                found = True
                
        for lev in range(self.ell+1,self.L+1):
            assert self.full[lev-self.ell]==1
        
            temp_share_data_0 = self.receiveMAndSplit(self.tcpSoc0)
            temp_share_data_1 = self.receiveMAndSplit(self.tcpSoc0)
            temp_share_data_01 = self.receiveMAndSplit(self.tcpSoc1)
            temp_share_data_11 = self.receiveMAndSplit(self.tcpSoc1)

            self.recBlockNum += 4

            temp_data_0 = (cutils.strXor(temp_share_data_0[0],temp_share_data_01[0]),cutils.strXor(temp_share_data_0[1],temp_share_data_01[1]))
            temp_data_1 = (cutils.strXor(temp_share_data_1[0],temp_share_data_11[0]),cutils.strXor(temp_share_data_1[1],temp_share_data_11[1]))
        
            if (not found) and temp_data_0[0]==a:# and temp_data_0[1]!='0':
                retrievedEle = temp_data_0
                found = True      
            if (not found) and temp_data_1[0]==a:# and temp_data_1[1]!='0':
                retrievedEle = temp_data_1
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
    
    coram = ORAMClient(NN, "noLog")
    coram.oramClientInitialization(A)
    OP = ["w", "r"]
    access_times = 4*NN-1#2**10#1#len(A)//2 513#
    error_times = 0
    pbar = tqdm(total=access_times)
    bb = time.time()
    for i in range(access_times):
        index = random.randint(0,len(A)-1)#random.randint(0,1)#random.randint(0,1)#random.randint(0,len(A)-1)
        k = A[index][0]
        v = str(random.randint(0,sys.maxsize))
        op = random.choice(OP)
        retrievedEle = coram.oramClientAccess(op, k, v)
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
        clientPermStoList.append(1)
        clientAccessStoList.append(2)

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
    pic = open(r'C:\Users\zxl\Desktop\LORAM\GitRespositery\hORAM\Result\OurBlockNum_{}.pkl'.format(NN), 'wb') #open(r'.\Ours\Result\BlockNum_{}.pkl'.format(NN), 'wb')
    pickle.dump(data,pic)
    pic.close()



