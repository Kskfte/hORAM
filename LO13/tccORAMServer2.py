import server
import math
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import copy
import tutils
import time

class tORAMServer:

    def __init__(self) -> None: #, c, ellCuckoo, countQ, countS, maxLevel all+1 dORAM.OldEmpty
        """
        Receive data size
        """
        self.byteOfComm = 1024
        self.tcpSoc = server.tcpServer(self.byteOfComm)
        self.N = int(self.tcpSoc.receiveMessage())
        """
        Parameters initilization
        """
        self.lenStash = math.ceil(math.log2(self.N))
        self.c = 2*self.lenStash
        self.maxLevel = 1 + math.ceil(math.log2(self.N/(self.c)))
        self.ellCuckoo = min(self.maxLevel, math.ceil(math.log2(math.log2(self.N))))
        #self.ellCuckoo = min(self.maxLevel, math.ceil(math.log2(math.pow(math.log2(self.N), 6)))) # (int)(7*math.log2(math.log2(N)))
        self.countQ = 0 # count access times
        self.countS = 0 # count dummy elements
        """
        The first level is the stash: stash0, stash1
        level = 2, 4, 6,..., in S0: server0Table[level//2]
        3, 5, 7,..., in S1: server0Table[(level-1)//2]
        """
        self.cuckooAlpha = math.ceil(math.log2(self.N))
        self.cuckooEpsilon = 0.01
        self.maxLevelCap = (int)((1+self.cuckooEpsilon)*(self.c*2**(self.maxLevel-1)))
        self.emptyForm = (bytes(16),"-1","-1")
        self.eachBucketCapacity = math.ceil(3*math.log2(self.N)/(math.log2(math.log2(self.N))))
        self.threshold_evict = self.cuckooAlpha*math.ceil(math.log2(self.N))

        self.stash1 = [self.emptyForm for i in range(self.c//2)] # (tag, k,v)
        self.server1Table = []
        self.server1Table.append([self.emptyForm])

        self.full = [0 for i in range(self.maxLevel+1)]

        self.availS = False

        """
        Initilize the table
        """
        for i in range(3, self.maxLevel+1, 2):
            nowCap = self.c*(2**(i-1))
            if i<self.ellCuckoo:
                self.server1Table.append([[self.emptyForm for _ in range(self.eachBucketCapacity)] for _ in range(nowCap)])
            else:
                self.server1Table.append([[self.emptyForm for _ in range((int)((1+self.cuckooEpsilon)*nowCap))],[self.emptyForm for _ in range((int)((1+self.cuckooEpsilon)*nowCap))]])

    def tableFullInit(self):
        self.stash1 = [self.emptyForm for i in range(self.c//2)] # (tag, k,v)
        self.server1Table = []
        self.server1Table.append([(bytes(16),"-1","-1")])
        """
        Initilize the table
        """
        for i in range(3, self.maxLevel+1, 2):
            nowCap = self.c*(2**(i-1))
            if i<self.ellCuckoo:
                self.server1Table.append([[self.emptyForm for _ in range(self.eachBucketCapacity)] for _ in range(nowCap)])
            else:
                self.server1Table.append([[self.emptyForm for _ in range((int)((1+self.cuckooEpsilon)*nowCap))],[self.emptyForm for _ in range((int)((1+self.cuckooEpsilon)*nowCap))]])


    def tableInit(self, lev):
        nowCap = self.c*(2**(lev-1))
        if lev<self.ellCuckoo:
            return [[self.emptyForm for i in range(self.eachBucketCapacity)] for j in range(nowCap)]
        else:
            return [[self.emptyForm for i in range((int)((1+self.cuckooEpsilon)*nowCap))],[self.emptyForm for i in range((int)((1+self.cuckooEpsilon)*nowCap))]]
    
    def posDictInit(self):
        return [{},{}]
    
    def stashInit(self):
        return [self.emptyForm for i in range(self.c//2)]
      
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
        
    def tORAMServerInitialization(self): # S0
        """
        Process
        """
        if self.maxLevel>>1<<1==self.maxLevel: # process for S0  
            self.availS = True
            maxLevelKey = tutils.strToBytes(self.tcpSoc.receiveMessage())
            temp_table = self.tableInit(self.maxLevel)
            temp_stash = []
            temp_dict = self.posDictInit()
            for _ in range(self.N):
                tag,k,v = tutils.unpackStrToM(self.tcpSoc.receiveMessage())
                temp_pos0,temp_pos1 = tutils.cuckooHashPosition(maxLevelKey,tag,self.maxLevelCap)
                tutils.cuckooHash((tag,k,v),temp_pos0,temp_pos1,temp_table,temp_stash,temp_dict,self.threshold_evict)
            stashLen = len(temp_stash)
            while len(temp_stash)<self.lenStash:
                temp_stash.append(self.emptyForm)
            
            self.tcpSoc.sendMessage(str(stashLen))
        
            for i in range(2):
                for tagKV in temp_table[i]:
                    self.tcpSoc.sendMessage(tutils.packMToStr(tagKV))
            self.tcpSoc.sendMessage("Done")

            for tagKV in temp_stash:
                    self.tcpSoc.sendMessage(tutils.packMToStr(tagKV))
            self.tcpSoc.sendMessage("Done")

        else:
            self.availS = False
            for i in range(2):
                for j in range(self.maxLevelCap):
                    mes = self.tcpSoc.receiveMessage()
                    tagKV = tutils.unpackStrToM(mes)
                    self.server1Table[(self.maxLevel-1)//2][i][j]=tagKV
            for i in range(self.lenStash):
                mes = self.tcpSoc.receiveMessage()
                tagKV = tutils.unpackStrToM(mes)
                self.stash1[i]=tagKV
        self.full[self.maxLevel]=1

    def tORAMServerAccess(self):
        for tagKV in self.stash1:
            self.tcpSoc.sendMessage(tutils.packMToStr(tagKV))
        self.tcpSoc.sendMessage("Done")

        for lev in range(3,self.maxLevel+1,2):
            if self.full[lev]==0:
                continue
            if lev<self.ellCuckoo:
                pos = int(self.tcpSoc.receiveMessage())
                for i in range(self.eachBucketCapacity):
                    self.tcpSoc.sendMessage(tutils.packMToStr(self.server1Table[(lev-1)//2][pos][i]))
                    self.server1Table[(lev-1)//2][pos][i] = tutils.unpackStrToM(self.tcpSoc.receiveMessage())
            else:
                posL = self.tcpSoc.receiveMessage().split( )
                pos0,pos1 = int(posL[0]),int(posL[1])
                #print((pos0,pos1))
                self.tcpSoc.sendMessage(tutils.packMToStr(self.server1Table[(lev-1)//2][0][pos0]))
                self.tcpSoc.sendMessage(tutils.packMToStr(self.server1Table[(lev-1)//2][1][pos1]))
                self.server1Table[(lev-1)//2][0][pos0] = tutils.unpackStrToM(self.tcpSoc.receiveMessage())
                self.server1Table[(lev-1)//2][1][pos1] = tutils.unpackStrToM(self.tcpSoc.receiveMessage())
        
        for i in range(len(self.stash1)):
            self.tcpSoc.sendMessage(tutils.packMToStr(self.stash1[i]))
            self.stash1[i] = tutils.unpackStrToM(self.tcpSoc.receiveMessage())
        self.tcpSoc.sendMessage("Done")

        if self.availS:
            self.stash1[self.stash1.index(self.emptyForm)] = tutils.unpackStrToM(self.tcpSoc.receiveMessage())
                
        self.countQ+=1

        #print(self.countQ)
        #print(self.lenStash)

        if self.countQ%self.lenStash==0:
            rebuildL = False
            #print(self.full)
            for i in range(2,self.maxLevel):
                if self.full[i]==0:
                    self.tORAMServerRebuild(i)
                    print(i)
                    #print(self.server1Table[(i-1)//2])
                    #print(self.stash1)
                    rebuildL = True
                    break
            if not rebuildL:
                self.tORAMServerRebuildL()
                print(self.maxLevel)
                #print(self.server1Table[(self.maxLevel-1)//2])
                #print(self.stash1)

    def tORAMServerRebuild(self, rebLev):
        if rebLev>>1<<1==rebLev:
            tempArray = copy.deepcopy(self.stash1)
            self.stash1 = self.stashInit()
            for ilev in range(3,rebLev,2):
                if ilev<self.ellCuckoo:
                    for tagKVList in self.server1Table[(ilev-1)//2]:
                        tempArray.extend(tagKVList)
                else:
                    tempArray.extend(self.server1Table[(ilev-1)//2][0])
                    tempArray.extend(self.server1Table[(ilev-1)//2][1])

                self.server1Table[(ilev-1)//2] = self.tableInit(ilev)

            random.shuffle(tempArray)

            for tagKV in tempArray:
                self.tcpSoc.sendMessage(tutils.packMToStr(tagKV))
            self.tcpSoc.sendMessage("Done")

            rebLevKey = tutils.strToBytes(self.tcpSoc.receiveMessage())

            
            temp_table = self.tableInit(rebLev)
            temp_stash = []
            if rebLev<self.ellCuckoo:
                while True:
                    mess = self.tcpSoc.receiveMessage()
                    if mess=="Done":
                        break
                    tag,k,v = tutils.unpackStrToM(mess)
                    temp_pos = tutils.standardHashPosition(rebLevKey,tag,len(temp_table))
                    tutils.standardHash((tag,k,v),temp_pos,temp_table,temp_stash)

                stashLen = len(temp_stash)
                while len(temp_stash)<self.lenStash:
                    temp_stash.append(self.emptyForm)
                
                self.tcpSoc.sendMessage(str(stashLen))

                for tagKVList in temp_table:
                    for tagKV in tagKVList:
                        self.tcpSoc.sendMessage(tutils.packMToStr(tagKV))
                self.tcpSoc.sendMessage("Done")
                for tagKV in temp_stash:
                    self.tcpSoc.sendMessage(tutils.packMToStr(tagKV))
                self.tcpSoc.sendMessage("Done")

            else:
                temp_dict = self.posDictInit()
                while True:
                    mess = self.tcpSoc.receiveMessage()
                    if mess=="Done":
                        break
                    tag,k,v = tutils.unpackStrToM(mess)
                    temp_pos0,temp_pos1 = tutils.cuckooHashPosition(rebLevKey,tag,len(temp_table[0]))
                    tutils.cuckooHash((tag,k,v),temp_pos0,temp_pos1,temp_table,temp_stash,temp_dict,self.threshold_evict)

                stashLen = len(temp_stash)
                while len(temp_stash)<self.lenStash:
                    temp_stash.append(self.emptyForm)
                
                self.tcpSoc.sendMessage(str(stashLen))

                for j in range(2):
                    for tagKV in temp_table[j]:
                        self.tcpSoc.sendMessage(tutils.packMToStr(tagKV))
                self.tcpSoc.sendMessage("Done")
                
                for tagKV in temp_stash:
                    self.tcpSoc.sendMessage(tutils.packMToStr(tagKV))
                self.tcpSoc.sendMessage("Done")

            for i in range(2,rebLev):
                self.full[i]=0
            self.full[rebLev]=1
            self.availS=True

        else:
            tempArray = copy.deepcopy(self.stash1)
            self.stash1 = self.stashInit()
            for ilev in range(3,rebLev,2):
                if ilev<self.ellCuckoo:
                    for tagKVList in self.server1Table[(ilev-1)//2]:
                        tempArray.extend(tagKVList)
                else:
                    tempArray.extend(self.server1Table[(ilev-1)//2][0])
                    tempArray.extend(self.server1Table[(ilev-1)//2][1])
                self.server1Table[(ilev-1)//2] = self.tableInit(ilev)
            random.shuffle(tempArray)

            while True:
                mess = self.tcpSoc.receiveMessage()
                if mess=="Done":
                    break
                tempArray.append(tutils.unpackStrToM(mess))
            
            for tagKV in tempArray:
                self.tcpSoc.sendMessage(tutils.packMToStr(tagKV))
            self.tcpSoc.sendMessage("Done")

            if rebLev<self.ellCuckoo:
                for i in range(len(self.server1Table[(rebLev-1)//2])):
                    for j in range(self.eachBucketCapacity):
                        mes = self.tcpSoc.receiveMessage()
                        tagKV = tutils.unpackStrToM(mes)
                        self.server1Table[(rebLev-1)//2][i][j]=tagKV
                for i in range(self.lenStash):
                    mes = self.tcpSoc.receiveMessage()
                    tagKV = tutils.unpackStrToM(mes)
                    self.stash1[i]=tagKV
            else:
                for i in range(2):
                    for j in range(len(self.server1Table[(rebLev-1)//2][0])):
                        mes = self.tcpSoc.receiveMessage()
                        tagKV = tutils.unpackStrToM(mes)
                        self.server1Table[(rebLev-1)//2][i][j]=tagKV
                for i in range(self.lenStash):
                    mes = self.tcpSoc.receiveMessage()
                    tagKV = tutils.unpackStrToM(mes)
                    self.stash1[i]=tagKV
            
            for i in range(2,rebLev):
                self.full[i]=0
            self.full[rebLev]=1
            self.availS=False

            #print(self.server1Table[(rebLev-1)//2])


    def tORAMServerRebuildL(self):

        """
        Process
        """
        if self.maxLevel>>1<<1==self.maxLevel:
            maxLevelKey = tutils.strToBytes(self.tcpSoc.receiveMessage())
            temp_table = self.tableInit(self.maxLevel)
            temp_stash = []
            temp_dict = self.posDictInit()
            for _ in range(self.N):
                self.tORAMServerReadOnly()

                tag,k,v = tutils.unpackStrToM(self.tcpSoc.receiveMessage())
                temp_pos0,temp_pos1 = tutils.cuckooHashPosition(maxLevelKey,tag,self.maxLevelCap)
                tutils.cuckooHash((tag,k,v),temp_pos0,temp_pos1,temp_table,temp_stash,temp_dict,self.threshold_evict)
            stashLen = len(temp_stash)
            while len(temp_stash)<self.lenStash:
                temp_stash.append(self.emptyForm)
            
            self.tcpSoc.sendMessage(str(stashLen))
        
            for i in range(2):
                for tagKV in temp_table[i]:
                    self.tcpSoc.sendMessage(tutils.packMToStr(tagKV))
            self.tcpSoc.sendMessage("Done")

            for tagKV in temp_stash:
                    self.tcpSoc.sendMessage(tutils.packMToStr(tagKV))
            self.tcpSoc.sendMessage("Done")
            
            self.availS=True    
            self.tableFullInit()

        else:
            for _ in range(self.N):
                self.tORAMServerReadOnly()
            self.availS = False
            self.tableFullInit()
            for i in range(2):
                for j in range(self.maxLevelCap):
                    mes = self.tcpSoc.receiveMessage()
                    tagKV = tutils.unpackStrToM(mes)
                    self.server1Table[(self.maxLevel-1)//2][i][j]=tagKV
            for i in range(self.lenStash):
                mes = self.tcpSoc.receiveMessage()
                tagKV = tutils.unpackStrToM(mes)
                self.stash1[i]=tagKV

        for i in range(2,self.maxLevel):
            self.full[i]=0
        self.full[self.maxLevel]=1

    def tORAMServerReadOnly(self):
        for tagKV in self.stash1:
            self.tcpSoc.sendMessage(tutils.packMToStr(tagKV))
        self.tcpSoc.sendMessage("Done")

        for lev in range(3,self.maxLevel+1,2):
            if self.full[lev]==0:
                continue
            if lev<self.ellCuckoo:
                pos = int(self.tcpSoc.receiveMessage())
                for i in range(self.eachBucketCapacity):
                    self.tcpSoc.sendMessage(tutils.packMToStr(self.server1Table[(lev-1)//2][pos][i]))
            else:
                posL = self.tcpSoc.receiveMessage().split( )
                pos0,pos1 = int(posL[0]),int(posL[1])
                self.tcpSoc.sendMessage(tutils.packMToStr(self.server1Table[(lev-1)//2][0][pos0]))
                self.tcpSoc.sendMessage(tutils.packMToStr(self.server1Table[(lev-1)//2][1][pos1]))
        

if __name__=="__main__":
    soram = tORAMServer()
    soram.tORAMServerInitialization()
    access_times = 4*soram.N-1#513#4*soram.N-1
    for i in range(access_times):
        retrievedEle = soram.tORAMServerAccess()
    soram.tcpSoc.closeConnection()
