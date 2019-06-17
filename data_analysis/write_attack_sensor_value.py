#coding:utf-8
#py3.7
from scapy.all import *
from openpyxl import *
from scapy.contrib.modbus import *
import math
import struct
import string

config_file = open("config.conf","rb")
config_file_contents = config_file.readlines()
sensor_max_or_min = float(0)
sensor_threshold = float(0)
sensor_b = float(0)

def read_config(attack_sensor_index):
    global sensor_max_or_min
    global sensor_threshold
    global  sensor_b
    global config_file_contents
    for i in range(len(config_file_contents)):
        config_file_contents[i] = bytes.decode(config_file_contents[i])
        config_file_contents[i] = config_file_contents[i].strip("\n")
        config_file_contents[i] = config_file_contents[i].split(":")
    sensor_max_or_min = float(config_file_contents[int(attack_sensor_index-1)*3][1])
    sensor_threshold = float(config_file_contents[int(attack_sensor_index-1)*3+1][1])
    sensor_b = float(config_file_contents[int(attack_sensor_index-1)*3+2][1])

def return_sensor_value(time_index,ip_src):
    if(ip_src=="192.168.1.101"):
        sensor_value = sheet["C"+str(int(time_index))].value
    if(ip_src=="192.168.1.102"):
        sensor_value = sheet["D"+str(int(time_index))].value
    return sensor_value

def float_to_dec(hex_sensor_value):
    high_reg = hex_sensor_value[:4]
    high_reg = int(high_reg,16)
    low_reg = hex_sensor_value[4:]
    low_reg = int(low_reg,16)
    return high_reg,low_reg

def hex_to_dec(hex_sensor_value):
    high_dec = int(hex_sensor_value[:4],16)
    low_dec = int(hex_sensor_value[4:],16)
    return high_dec,low_dec

def dec_to_float(high_sensor_value, low_sensor_value):
    high_sensor_value = hex(high_sensor_value)[2:].zfill(4)
    low_sensor_value = hex(low_sensor_value)[2:].zfill(4)
    sensor_value = high_sensor_value + low_sensor_value
    float_sensor_value = struct.unpack("!f", bytes.fromhex(sensor_value))[0]
    hex_sensor_value = struct.pack(">f", float_sensor_value).hex().zfill(8)
    return hex_sensor_value, float_sensor_value

def calc_average_sensor_value(sensor_index):
    total_value = float(0)
    for step in range(10000):
        time_index = int(2 + (step) * 42) + sensor_index-1
    #print(type(total_value))
        total_value = total_value + sheet["C" + str(int(time_index))].value
    average_value = total_value/10000
    return  "%g"%average_value

def calc_sensor_b_value(sensor_index):
    total_value = float(0)
    for step in range(10000):
        time_index = int(2 + (step) * 42) + sensor_index-1
        sensor_pre_value = sheet["C" + str(int(time_index))].value
        sensor_act_value = sheet["G" + str(int(time_index))].value
        sub_value = abs(sensor_pre_value-sensor_act_value)
        total_value = total_value + sub_value
    total_value = total_value /10000
    return "%g"%total_value

def Surge_Attacks(step,sensor_pre_value):
    global sensor_max_or_min
    t = 0.0005
    S0=float(step*t)

    if(S0+t) > sensor_threshold:
        out_put_value = sensor_pre_value - sensor_b
    if(S0+t) <= sensor_threshold:
        out_put_value = sensor_max_or_min
    return out_put_value

def Bias_Attacks(step,sensor_pre_value):
    global sensor_threshold
    global sensor_b
    #print(sensor_threshold,sensor_b)
    c = float(sensor_threshold/step+sensor_b)
    #print(c)
    #print(c,sensor_pre_value)
    out_put_value = float(sensor_pre_value) + c
    return out_put_value

def Geometric_Attacks(step,sensor_pre_value):
    global sensor_threshold
    aerfa = 0.95
    yu_zhi = sensor_threshold
    n = 50
    bei_ta = (float(yu_zhi+n*0.00563433) * (pow(float(aerfa), -1) - 1)) / (1 - pow(float(aerfa), n))
    print(bei_ta)
    k = step * 0.0005
    out_put_value = sensor_pre_value + bei_ta * pow(aerfa, n - k)
    return out_put_value

def add_value(sensor_index):
    for step in range(10000):
        time_index = int(2 + (step) * 42) + sensor_index-1
        sensor_pre_value = sheet["C" + str(int(time_index))].value
        out_put_value = sheet["F" + str(int(time_index))].value
        sheet["E" + str(int(2+step))] = out_put_value-sensor_pre_value


if __name__ == '__main__':
    wb = load_workbook("sensor_predict.xlsx")
    sheet = wb["test"]
    read_config(2)

    sensor_index = 4 #attack sensor number

    #------------------surge attack---------------------
    for step in range(0,1000):
        time_index = int(2 + step * 42) +sensor_index-1
        pre_value = sheet["C"+str(time_index)].value
        out_value  = Surge_Attacks(step,pre_value)
        sheet["H"+str(time_index)] = out_value
    # ------------------surge attack---------------------


    # ------------------bias attack---------------------

    n = 100
    #weirao gongji
    for step in range(0,10000):
        time_index = int(2 + step * 42) +sensor_index-1
        pre_value = sheet["C"+str(time_index)].value
        out_value  = Bias_Attacks(10000,pre_value)
        sheet["I"+str(time_index)] = out_value
    # ------------------bias attack---------------------


    # ------------------geometric attack---------------------
    for step in range(0,10000):
        time_index = int(2 + step * 42) +sensor_index-1
        pre_value = sheet["C"+str(time_index)].value
        out_value  = Geometric_Attacks(10000,pre_value)
        sheet["J"+str(time_index)] = out_value
    # ------------------geometric attack---------------------

    #------------------calc b--------------------------------
    sensor_index = 15
    bi = calc_sensor_b_value(sensor_index)
    print(bi)
    #-------------------calc b--------------------------------

    #-------------------calc average sensor value---------------------
    average_value = calc_average_sensor_value(15)
    print(average_value)
    # -------------------calc average sensor value---------------------

    #--------------------test search sensor value----------------------
    """
    while (1):
        t = input("input time:")
        t = float(t) * 10000
        t = int(t)
        step = t / 5
        time_index = int(2 + step * 42)
        time = sheet["A"+str(time_index)].value
        ip_src = input("ip:")
        sensor_index = input("input sensor:")
        sensor_index = int(sensor_index)-1
        index = time_index + sensor_index
        sensor_value = return_sensor_value(time_index=index,ip_src=ip_src)
        print("sim_time:",time,"ip_src_addr:",ip_src,"sensor_value",sensor_value)
        #print(type(sensor_value))
        hex_value = struct.pack(">f", sensor_value).hex()
        #print(hex_value)
        hex_value = hex_value.zfill(8)
        #print(hex_value)
        high_dec,low_dec = hex_to_dec(hex_value)
        print("sim_time:", time, "ip_src_addr:", ip_src, "reg0:", high_dec,"reg1:",low_dec)
        #hex_sensor_value, sensor_value_index = dec_to_float(high_dec, low_dec)
        #print(type(sensor_value))
        #print("sim_time:", time, "ip_src_addr:", ip_src, "sensor_value", "%g"%sensor_value_index)
    """
    #--------------------test search sensor value----------------------
    wb.save("sensor_predict.xlsx")
