# -*- coding: utf-8 -*-
"""
Created on Wed Jun 22 00:46:56 2022

@author: KKS
"""

import scapy.all as sp
import time
import requests,json
from _thread import *
from threading import Thread

def test(packet):
    src_ip = packet[sp.IP].src  
    length = packet[sp.IP].len
    if src_ip == ip and length != 40:
        data  = str(packet[sp.IP].payload).split('(')[-1][3:-4].split(' ')
        if data[0] == "info":
            datas["Voltage"]   = str(int(data[4])/1000) + " kV"
            datas["Current"]   = str(int(data[5])/1000) + " mA"
            datas["IGVoltage"] = str(int(data[7])    ) + " mV"
        if data[0] == "pval_cw":
            datas["Colling water"] = str(int(data[5])/1000) + " L/min"
def log(): #send device log data to other websites
    while True:
        try:
            sp.sniff(filter="tcp",iface=internet_i,prn=test,timeout=2)
            url = "http://192.168.2.100:8000/" + "XRD"
            re  = requests.post(url,str(datas))
            json_dict = json.loads(re.content.decode('utf-8'))
        except:
            print("Log Error")
        time.sleep(8)
if __name__ == "__main__":
    datas = {}
    s_log = Thread(target = log)
    s_log.start()
    ip = "192.168.127.10" # Use connection with Rigaku Devices. In this case, RIGAKU SmartLab XRD was used.
    internet_i=sp.conf.route.route(ip)[0]
