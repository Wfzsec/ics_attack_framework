数据分析模块主要用于记录正常的modbus/tcp通信传感器数据以及写入te_attack文件夹中3个含有攻击数据的excel
----process_te_pcap.py文件主要用于处理modbus/tcp数据包
----write_attack_sensor_value.py文件主要用于构造浪涌攻击、微扰攻击、几何攻击的本地excel
----config.conf主要为记录的需要攻击的传感器的关键参数值
----te.pcap为te返回到plc端的传感器数据包
----sensor_predict为根据传感器正常生产值生成的预期值