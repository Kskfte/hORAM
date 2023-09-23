import cuckooHash
import math

class hORAM:

    def __init__(self, arr, ) -> None:
        """
        We set lambda = len(arr) and size of each block is O(lambda*log n).
        """
        self.ell = math.ceil(math.log2(math.log2(len(arr))))
        self.level = math.ceil(math.log2(len(arr)))

        """
        Element zone.
        """
        #self.EleZoneOne = [None]*
        
        pass