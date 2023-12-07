
from statistics import mean
from scapy.all import *
from scipy import stats

import sys
import numpy as np
import math
import random
import matplotlib.pyplot as plt




def get_dispersion(r_probe):
    #max_len = 20000
    last_pkt = r_probe[3]
    r_dispersion = np.array([])
    # f = open("dispersions1000","w")
    start = 0
    string = ""
    mean_disps = []
    median_disps = []
    x = []
    y = []
    first = True
    start_time = 0
    end_time = 0
    for i in range(0, len(r_probe)):  
        if("IP" in r_probe[i]):
            if(last_pkt):
                if first:
                    first = False
                    start_time = float(r_probe[i].time)
                    
                dispersion = float(r_probe[i].time - last_pkt.time)
                last_pkt=r_probe[i]
                print(dispersion,i)
                r_dispersion = np.append(r_dispersion,dispersion)
                end_time = float(r_probe[i].time)
    range1 = end_time - start_time
    print("stats",np.mean(r_dispersion), np.median(r_dispersion),np.std(r_dispersion))
    '''for i in range(15164,max_len):  
        if("IP" in r_probe[i]):
                
                x = np.append(x, float(r_probe[i].time) - start_time)

                y = np.append(y, float(r_probe[i].time - last_pkt.time)) 
                last_pkt=r_probe[i]
                
    f = open("malware_floodx", "w")
    f2 = open("malware_floody", "w")
    f.write("[")
    xcount = 0
    for i in x:
       
        if xcount == len(x)-1:
            f.write((str(i)))
        else: 
             f.write(str(i))
             f.write(",")
        xcount +=1 
        
    f.write("]")
    
    f2.write("[")
    ycount = 0
    print(len(r_dispersion))
    for i in r_dispersion:
       
        if ycount == len(y)-1:
            f2.write((str(i)))
        else: 
             f2.write(str(i))
             f2.write(",")
        ycount +=1 
    f2.write("]")
    plt.title("Inter-packet dispersion")
    plt.plot(x,y)
    plt.xlabel("time")
    plt.ylabel("dispersion (us)")
    plt.grid(axis = 'y')
    plt.show()
    print("balls") '''
                # 




def main(filename):
    pcap = rdpcap(filename)
    get_dispersion(pcap)
    


if __name__=="__main__":
    rcv_filename = sys.argv[1]
    
    main(rcv_filename)