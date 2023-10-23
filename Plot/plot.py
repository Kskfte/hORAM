import matplotlib.pyplot as plt
import numpy as np
import pickle
import os
from matplotlib.ticker import MaxNLocator

def plot_time(whichS, Y, savePath, NN):
    access_times = []
    for i in range(len(Y[0])):
        access_times.append((i+1)*NN//(2**4))
    #plt.plot(access_times, send_block, 'b*--', alpha=0.5, linewidth=1, label='SendBlock')
    #plt.plot(access_times, rec_block, 'rs--', alpha=0.5, linewidth=1, label='RecBlock')
    #plt.plot(access_times, bandwidth, 'go--', alpha=0.5, linewidth=1, label='AmortizedBandwidth')
    plt.rcParams.update({
    "legend.fancybox": False,
    "legend.frameon": True,
    "text.usetex": True,
    "font.family": "serif",
    "font.serif": ["Times"], #注意这里是Times，不是Times New Roman
    "font.size":25})
    plt.figure()
    plt.plot(access_times, Y[1], 'bd--', alpha=0.5, linewidth=1, label=whichS[1])
    plt.plot(access_times, Y[2], 'go--', alpha=0.5, linewidth=1, label=whichS[2])
    plt.plot(access_times, Y[0], 'r*--', alpha=0.5, linewidth=1, label=whichS[0])
    plt.plot(access_times, Y[3], 'yp--', alpha=0.5, linewidth=1, label=whichS[3])


    #plt.legend() 
    plt.xlabel('Access times')
    plt.ylabel('Amortized time (in s)')
    
    plt.yscale('log')
    plt.ylim(10**(-1),10**2)
    plt.grid()

    #plt.title('TotalBlockNum: {}'.format(NN))
    plt.savefig(os.path.join(savePath,'TimeAV_{}.pdf'.format(NN)), bbox_inches = 'tight', dpi = 600)
    plt.close()

def plot_bandwidth(whichS, Y, savePath, NN):
    access_times = []
    for i in range(len(Y[0])):
        access_times.append((i+1)*NN//(2**4))
    #plt.plot(access_times, send_block, 'b*--', alpha=0.5, linewidth=1, label='SendBlock')
    #plt.plot(access_times, rec_block, 'rs--', alpha=0.5, linewidth=1, label='RecBlock')
    #plt.plot(access_times, bandwidth, 'go--', alpha=0.5, linewidth=1, label='AmortizedBandwidth')
    plt.rcParams.update({
    "legend.fancybox": False,
    "legend.frameon": True,
    "text.usetex": True,
    "font.family": "serif",
    "font.serif": ["Times"], #注意这里是Times，不是Times New Roman
    "font.size":25})
    fsize = 25

    plt.figure()
    plt.plot(access_times, Y[1], 'bd--', alpha=0.5, linewidth=1, label=whichS[1])
    plt.plot(access_times, Y[2], 'go--', alpha=0.5, linewidth=1, label=whichS[2])
    plt.plot(access_times, Y[0], 'r*--', alpha=0.5, linewidth=1, label=whichS[0]+'\&'+whichS[3])

    #plt.legend() 
    plt.xlabel('Access times')
    plt.ylabel('Amortized bandwidth')
    plt.grid()
    #plt.title('TotalBlockNum: {}'.format(NN))
    #plt.yscale('log')
    #plt.ylim(10**1,10**3)
    plt.savefig(os.path.join(savePath,'BandwidthAV_{}.pdf'.format(NN)), bbox_inches = 'tight', dpi = 600)
    plt.close()

def plot_eachBandwidth(whichS, Y, savePath, NN):
    access_times = []
    for i in range(len(Y[0])):
        access_times.append(i+1)
    #plt.plot(access_times, send_block, 'b*--', alpha=0.5, linewidth=1, label='SendBlock')
    #plt.plot(access_times, rec_block, 'rs--', alpha=0.5, linewidth=1, label='RecBlock')
    #plt.plot(access_times, bandwidth, 'go--', alpha=0.5, linewidth=1, label='AmortizedBandwidth')
    plt.rcParams.update({
    "legend.fancybox": False,
    "legend.frameon": True,
    "text.usetex": True,
    "font.family": "serif",
    "font.serif": ["Times"], #注意这里是Times，不是Times New Roman
    "font.size":25})
    fsize = 25

    plt.figure()
    plt.plot(access_times, Y[1], 'bx', markerfacecolor='white',markersize=5, alpha=0.5, linewidth=1, label=whichS[1])
    plt.plot(access_times, Y[2], 'gs', markerfacecolor='white',markersize=5, alpha=0.5, linewidth=1, label=whichS[2])
    plt.plot(access_times, Y[0], 'ro', markerfacecolor='white',markersize=5, alpha=0.5, linewidth=1, label=whichS[0]+'\&'+whichS[3])
    

    plt.legend() 
    plt.xlabel('|Access|')
    plt.ylabel('Bandwidth')
    plt.grid()
    #plt.title('TotalBlockNum: {}'.format(NN))
    plt.yscale('log')
    #plt.ylim(10**(0),10**3)
    plt.savefig(os.path.join(savePath,'BandwidthEachAcc_{}.pdf'.format(NN)), bbox_inches = 'tight', dpi = 600)
    plt.close()

def plot_eachTime(whichS, Y, savePath, NN):
    access_times = []
    for i in range(len(Y[0])):
        access_times.append(i+1)
    #plt.plot(access_times, send_block, 'b*--', alpha=0.5, linewidth=1, label='SendBlock')
    #plt.plot(access_times, rec_block, 'rs--', alpha=0.5, linewidth=1, label='RecBlock')
    #plt.plot(access_times, bandwidth, 'go--', alpha=0.5, linewidth=1, label='AmortizedBandwidth')
    plt.rcParams.update({
    "legend.fancybox": False,
    "legend.frameon": True,
    "text.usetex": True,
    "font.family": "serif",
    "font.serif": ["Times"], #注意这里是Times，不是Times New Roman
    "font.size":25})
    fsize = 25

    plt.figure()
    plt.plot(access_times, Y[1], 'bx--', markerfacecolor='white',markersize=5, alpha=0.5, linewidth=1, label=whichS[1])
    plt.plot(access_times, Y[2], 'g|--', markerfacecolor='white',markersize=5, alpha=0.5, linewidth=1, label=whichS[2])
    plt.plot(access_times, Y[0], 'r.--', markerfacecolor='white',markersize=5, alpha=0.5, linewidth=1, label=whichS[0])
    plt.plot(access_times, Y[3], 'k.--', markerfacecolor='white',markersize=5, alpha=0.5, linewidth=1, label=whichS[3])
    

    plt.legend() 
    plt.xlabel('|Access|')
    plt.ylabel('Time')
    plt.grid()
    #plt.title('TotalBlockNum: {}'.format(NN))
    plt.yscale('log')
    #plt.ylim(10**(0),10**3)
    plt.savefig(os.path.join(savePath,'TimeEach_{}.pdf'.format(NN)), bbox_inches = 'tight', dpi = 600)
    plt.close()

def plot_clientPermSto(whichS, Y, savePath, NN):
    access_times = []
    for i in range(len(Y[0])):
        access_times.append(i+1)
    #plt.plot(access_times, send_block, 'b*--', alpha=0.5, linewidth=1, label='SendBlock')
    #plt.plot(access_times, rec_block, 'rs--', alpha=0.5, linewidth=1, label='RecBlock')
    #plt.plot(access_times, bandwidth, 'go--', alpha=0.5, linewidth=1, label='AmortizedBandwidth')
    plt.rcParams.update({
    "legend.fancybox": False,
    "legend.frameon": True,
    "text.usetex": True,
    "font.family": "serif",
    "font.serif": ["Times"], #注意这里是Times，不是Times New Roman
    "font.size":25})
    fsize = 25

    plt.figure()
    plt.gca().yaxis.set_major_locator(MaxNLocator(integer=True))
    plt.plot(access_times, Y[1], 'bd--', alpha=0.5, linewidth=1, label=whichS[1])
    plt.plot(access_times, Y[2], 'go--', alpha=0.5, linewidth=1, label=whichS[2])
    plt.plot(access_times, Y[0], 'r*--', alpha=0.5, linewidth=1, label=whichS[0]+'\&'+whichS[3])

    plt.legend() 
    plt.xlabel('Access times')
    plt.ylabel('Client Storage')
    plt.grid()
    #plt.title('TotalBlockNum: {}'.format(NN))
    plt.savefig(os.path.join(savePath,'ClientPermStoAV_{}.pdf'.format(NN)), bbox_inches = 'tight', dpi = 600)
    plt.close()

def plot_clientTempSto(whichS, Y, savePath, NN):
    access_times = []
    for i in range(len(Y[0])):
        access_times.append((i+1)*NN//(2**4))
    #plt.plot(access_times, send_block, 'b*--', alpha=0.5, linewidth=1, label='SendBlock')
    #plt.plot(access_times, rec_block, 'rs--', alpha=0.5, linewidth=1, label='RecBlock')
    #plt.plot(access_times, bandwidth, 'go--', alpha=0.5, linewidth=1, label='AmortizedBandwidth')

    plt.rcParams.update({
    "legend.fancybox": False,
    "legend.frameon": True,
    "text.usetex": True,
    "font.family": "serif",
    "font.serif": ["Times"], #注意这里是Times，不是Times New Roman
    "font.size":25})
    fsize = 25
    plt.figure()
    plt.plot(access_times, Y[1], 'bd--', alpha=0.5, linewidth=1, label=whichS[1])
    plt.plot(access_times, Y[2], 'go--', alpha=0.5, linewidth=1, label=whichS[2])
    plt.plot(access_times, Y[0], 'r*--', alpha=0.5, linewidth=1, label=whichS[0])
    plt.plot(access_times, Y[3], 'yp--', alpha=0.5, linewidth=1, label=whichS[3])

    #plt.legend(fontsize=fsize)
    plt.xticks(fontsize=fsize) 
    plt.yticks(fontsize=fsize) 
    plt.xlabel('Access times',fontsize=fsize)
    plt.ylabel('Client Temporary Storage',fontsize=fsize)
    plt.grid()
    plt.savefig(os.path.join(savePath,'ClientTempStoAV_{}.pdf'.format(NN)), bbox_inches = 'tight', dpi = 600)
    plt.close()

if __name__=="__main__":
    NN = 2**12
    interval = NN//(2**4)
    rootPath = r'C:\Users\zxl\Desktop\LORAM\GitRespositery\hORAM\Result'
    savePath = r'C:\Users\zxl\Desktop\LORAM\GitRespositery\hORAM\Plot'
    whichScheme = ['Our','LO13','GKW18','OursLog']
    whichS2 = ['Ours','LO13','GKW18','Ours*']
    Time = []
    TotalTime = []
    AmortizedBandwidth = []
    #EachAccBandwidth = []
    ClientPermSto = []
    ClientTempSto = []
    
    for i in range(len(whichScheme)):
        pic2 = open(os.path.join(rootPath,'{}BlockNum_{}.pkl'.format(whichScheme[i],NN)),'rb')
        
        data = pickle.load(pic2)
        #print(data)
        #print(type(data))
        tmpTime = []
        tmpPerm = []
        tmpTemp = []
        tmpSend = []
        tmpRec = []

        #tmpTotalSend = []
        #tmpTotalRec = []
        print(data['ClientAccessSto'])
        for j in range(0, len(data['ConsumeTime']), interval):
            tmpTime.append(data['ConsumeTime'][j]/(j+1))
            tmpPerm.append(data['ClientPermSto'][j])
            tmpTemp.append(data['ClientAccessSto'][j])
            #print(whichScheme[i])
            tmpSend.append(data['SendBlock'][j]/(j+1))
            tmpRec.append(data['RecBlock'][j]/(j+1))

            #tmpTotalSend
        #print(send_block)
        #print(rec_block)
        Time.append(tmpTime)
        ClientPermSto.append(tmpPerm)
        ClientTempSto.append(tmpTemp)
        AmortizedBandwidth.append([(tmpSend[j]+tmpRec[j]) for j in range(len(tmpSend))])
        TotalTime.append([data['ConsumeTime'][0]])
        for j in range(1, len(data['SendBlock'])): 
            #EachAccBandwidth[i].append((data['SendBlock'][j]+data['RecBlock'][j]-data['SendBlock'][j-1]-data['RecBlock'][j-1])/2)
            TotalTime[i].append(data['ConsumeTime'][j])
        """
        EachAccBandwidth.append([(data['SendBlock'][0]+data['RecBlock'][0])/2])
        EachTime.append([data['ConsumeTime'][0]])
        for j in range(1, len(data['SendBlock'])): 
            EachAccBandwidth[i].append((data['SendBlock'][j]+data['RecBlock'][j]-data['SendBlock'][j-1]-data['RecBlock'][j-1])/2)
            EachTime[i].append(data['ConsumeTime'][j]-data['ConsumeTime'][j-1])
        """
        
        pic2.close()
    plot_time(whichS2,Time,savePath,NN)
    #plot_bandwidth(whichS2,AmortizedBandwidth,savePath,NN)
    #plot_eachBandwidth(whichS2,EachAccBandwidth,savePath,NN)
    #plot_eachTime(whichS2,TotalTime,savePath,NN)
    #plot_clientPermSto(whichS2,ClientPermSto,savePath,NN)
    #plot_clientTempSto(whichS2,ClientTempSto,savePath,NN)
