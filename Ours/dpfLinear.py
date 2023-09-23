import random
import math

"""
Linear PIR read
type(key) = str
type(value) = int
"""
class Client:

    def __init__(self, input_length):
        self.input_length = input_length
    
    def gen_keys(self, index):
        sk_0 = self.rand_string_01(self.input_length)
        sk_1 = self.generate_secondkey(sk_0, index)
        return sk_0, sk_1
    
    
    def rand_string_01(self, length):
        seed = "01"
        sa = []
        for i in range(length):
            sa.append(random.choice(seed))
        salt = ''.join(sa)
        return salt

    def generate_secondkey(self, sk_0, index):
        rep = '1'
        if sk_0[index] == '1':
            rep = '0'
        return sk_0[:index]+rep+sk_0[index+1:]

class Server:
    
    def __init__(self, input_array):
        self.input_array = input_array

    def eval_key(self, sk):
        res = 0
        for i in range(len(self.input_array)):
            res ^= (self.input_array[i]*((int)(sk[i])-(int)('0')))
        return res

if __name__=="__main__":
    input_array = [576,4235,287,97,7,4,3,2,10,11,12,197,17,14,23,422]
    client = Client(len(input_array))
    server1 = Server(input_array)
    server2 = Server(input_array)
    index = 4
    sk_0, sk_1 = client.gen_keys(4)
    result = server1.eval_key(sk_0)^server2.eval_key(sk_1)
    print(result)


