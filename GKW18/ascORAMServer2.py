import server
import math
import random
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
import copy
import gutils
import time

class aORAMServer:
    def __init__(self) -> None: #, c, ellCuckoo, countQ, countS, maxLevel all+1 dORAM.OldEmpty
        """
        Receive data size
        """
        self.byteOfComm = 1024
        self.tcpSoc = server.tcpServer(self.byteOfComm)
        self.N = int(self.tcpSoc.receiveMessage())
        self.A = 1
        self.Z = 2
        self.ctr = -1
        self.treeDepth = math.ceil(math.log2(self.N))# 1,2,...,treedepth
        self.leafNum = self.N

        self.emptyForm = ("-1","-1")

        self.Tree = [[[self.emptyForm for _ in range(self.Z)] for j in range(2**i)] for i in range(self.treeDepth+1)]
    
    
    def aORAMServerInitialization(self):
        for _ in range(self.N):
            (k,v,leafPos) = gutils.unpackStrToKVPos(self.tcpSoc.receiveMessage())
            tempWriteFlag = False
            for i in range(self.treeDepth,0,-1):
                nowLevPos = gutils.leafPosTolevPos(leafPos,i,self.treeDepth)
                for j in range(self.Z):
                    if self.Tree[i][nowLevPos][j]==self.emptyForm:
                        self.Tree[i][nowLevPos][j]=(k,v)
                        tempWriteFlag = True
                        break
                if tempWriteFlag:
                    break
    
       
    def aORAMServerAccess(self):
        pk,ck,k1 = gutils.strToDpfKeys(self.tcpSoc.receiveMessage())
        Bi = gutils.dpfEvalAll(pk,ck,self.leafNum,1,k1)
        tempBiList = [[-1 for j in range(2**i)] for i in range(self.treeDepth+1)]
        tempBiList[self.treeDepth]=Bi

        for i in range(self.treeDepth-1,0,-1):
            for j in range(len(tempBiList[i])):
                tempBiList[i][j]=tempBiList[i+1][2*j]^tempBiList[i+1][2*j+1]
        
        for i in range(1,self.treeDepth+1): 
            for z in range(self.Z):
                (tmpK,tmpV) = ("0","0")
                for j in range(len(self.Tree[i])):
                    (tmpK,tmpV) = (gutils.strXor(tmpK,gutils.strMul01(tempBiList[i][j],self.Tree[i][j][z][0])), gutils.strXor(tmpV,gutils.strMul01(tempBiList[i][j],self.Tree[i][j][z][1])))
                self.tcpSoc.sendMessage(gutils.packKVToStr((tmpK,tmpV)))  

        self.ctr = (self.ctr+1)%self.leafNum
        if self.ctr%self.A==0:
            self.aORAMServerEvict()             


    def aORAMServerEvict(self):
        leafPos = gutils.reverseBit(self.ctr,self.treeDepth)
   
        for i in range(1,self.treeDepth+1):
            pos = gutils.leafPosTolevPos(leafPos,i,self.treeDepth)#evictPath//(self.treeDepth-i)
            for j in range(self.Z):
                self.Tree[i][pos][j]=gutils.unpackStrToKV(self.tcpSoc.receiveMessage())

if __name__=="__main__":

    soram = aORAMServer()
    soram.aORAMServerInitialization()
    access_times = 4*soram.N-1#513#4*soram.N-1
    for i in range(access_times):
        retrievedEle = soram.aORAMServerAccess()
    soram.tcpSoc.closeConnection()