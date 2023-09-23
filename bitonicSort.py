import random
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


if __name__=="__main__":


    """
    
    """         
    l = 2**20
    A = []
    for i in range(l):
        A.append(random.randint(-l, l))
    bitonicSort = Bitonic(A, 1)
    for i in range(len(A)-1):
        assert(A[i]<=A[i+1])
    print(bitonicSort.compTimes)