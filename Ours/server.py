#Authors:xiaobei

######客户端创建######

import socket
from socket import *
import time
import struct
#创建一个socket

class tcpServer:
    def __init__(self,byteOfComm):
        self.byteOfComm = byteOfComm
        self.tcp_server = socket(AF_INET,SOCK_STREAM)
        self.tcp_server.bind(('',8000))
        self.tcp_server.listen(1)
        self.client_socket, _ = self.tcp_server.accept()

    def sendMessage(self, message):
        self.client_socket.sendall(struct.pack('i',len(message)))
        self.client_socket.sendall(message.encode("utf-8")) #.ljust(self.byteOfComm)

    def receiveMessage(self):
        int_length = 4
        dataL = b''
        while len(dataL) < int_length: #循环接收数据
            dataL += self.client_socket.recv(int_length - len(dataL))
        data_length = struct.unpack('i',dataL)[0]
        from_server_msg = b''
        while data_length>0:
            if data_length>self.byteOfComm:
                temp = self.client_socket.recv(self.byteOfComm)
            else:
                temp = self.client_socket.recv(data_length)
        #while len(from_server_msg) < data_length: #循环接收数据
            from_server_msg += temp
            data_length -= len(temp)
        #print(len(from_server_msg))
        return from_server_msg.decode("utf-8")
        

    def closeConnection(self):
        self.tcp_server.close()
        self.client_socket.close()

if __name__=="__main__":

    udpS = tcpServer(1024)
    LL = []
    NN = 2**8
    for i in range(NN):
        udpS.sendMessage(str(i))
    for i in range(NN):
        udpS.receiveMessage()

    
    for i in range(NN//2):
        udpS.sendMessage(str(i))
        udpS.receiveMessage()
    for i in range(NN//2):
        udpS.sendMessage(str(i))
        udpS.receiveMessage()

    for i in range(NN):
        pl = udpS.receiveMessage()
        udpS.sendMessage(str(i))
    
    for i in range(NN):
        #LL.append(str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1)+" "+str(i+1))
    #for i in range(len(LL)):
        #print(LL[i])
        udpS.receiveMessage()#sendMessage(str(i))
    for i in range(NN):
        udpS.sendMessage(str(i))
    udpS.closeConnection() 
"""
    def __init__(self) -> None:
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind(('', 4000))

    def sendMessage(self, message, addr, port): # message: str
        self.sock.sendto(message.encode('utf-8'), (addr, port))

    def receiveMessage(self, byteOfCom):
        recvData = self.sock.recvfrom(byteOfCom)
        return recvData[0].decode('utf-8'),recvData[1]

    def closeSocket(self):
        self.sock.close()

class udpServer:
    def __init__(self) -> None:
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind(('', 4000))
        m = self.sock.recvfrom(64)
        print(m)
        return m
    
    def sendMessage(self, message, addr, port): # message: str
        self.sock.sendto(message.encode('utf-8'), (addr, port))

    def receiveMessage(self, byteOfCom):
        m = self.sock.recvfrom(byteOfCom)
        print(m)
        return m

    def closeSocket(self):
        self.sock.close()

if __name__=="__main__":
    udpS = udpServer()
    #for i in range(3):
    #print(udpS.receiveMessage(64))
    udpS.closeSocket() 
    
def createConnection(): 
    udp_socket = socket(AF_INET,SOCK_STREAM)
    address = ('',8000)
    udp_socket.bind(address)
    udp_socket.listen(1)
    client_socket, _ = udp_socket.accept()
    return client_socket

def sendMessage(client_socket, message):
    client_socket.send(message.encode("utf-8"))

def receiveMessage(client_socket, byteOfComm):
    from_client_msg = client_socket.recv(byteOfComm)
    #加上.decode("gbk")可以解决乱码
    return from_client_msg.decode("utf-8")

def closeConnection(client_socket):
    client_socket.close()

if __name__=="__main__":
    client_socket = createConnection()
    for i in range(3):
        print(receiveMessage(client_socket, 32))
    closeConnection(client_socket)

"""

