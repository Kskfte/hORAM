# hORAM
Code for [LO13](https://eprint.iacr.org/2011/384.pdf), [GKW18](https://eprint.iacr.org/2018/005.pdf), [KM19](https://arxiv.org/pdf/1802.05145.pdf) and Ours.
## Deployments
Users need to deploy two servers and copy the corresponding two files ``*ORAMServer.py`` and ``*ORAMServer2.py`` on each server. The file ``server.py`` and other ``utils`` files are also needed to be copied in two servers. In addition, users require to modify the addresses and ports of two servers in ``client.py``.
## Test
For experimental comparisons, users can modify the database size and block size in ``*ORAMClient.py`` to test the results under different database and block size. Note because KM19 requires the use of oblivious sort to implement rebuild operations, which consumes a lot of time, users can first pre-test the cost of rebuild through ``SimOBuildClient.py`` and ``SimOBuildServer.py``, thereby accelerating the experiment.

