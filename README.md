# hORAM
Code for [LO13](https://eprint.iacr.org/2011/384.pdf), [GKW18](https://eprint.iacr.org/2018/005.pdf), and Our "Efficient Two-server ORAM with Practical Bandwidth and Constant Storage Cost".
## Implementations
Users need to deploy two servers and copy the two files ``*ORAMServer.py`` and ``*ORAMServer2.py`` on each server. In addition, the users also needs to modify the addresses and ports of two servers in ``client.py``.
## Test
For experimental comparisons, users can modify the database size and access times in ``*ORAMClient.py`` to test the results under databases of different sizes 

