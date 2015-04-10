#!/usr/bin/python
from socket import * 
from struct import *
from pymongo import Connection
from datetime import datetime
import signal
import time 
import os
from subprocess import Popen
import binascii
# Create socket and bind to address 

def SigTest(signum, stack):
	print "SIGHUP!"
	

UDPSock = socket(AF_INET,SOCK_DGRAM) 
UDPSock.bind(('',50000)) 
connection = Connection()
db = connection['nat_history']
records=db.records
signal.signal(signal.SIGHUP, SigTest)
timestamp = 0
firstRun=1
while (True): 
    # Check filetime
    newTimestamp = int(time.time())
    timeDiff = newTimestamp - timestamp
    if (timeDiff > 900)or(firstRun==1):
        if (firstRun==0):
             f.close
             Popen(['/bin/gzip',filename])
        dateTag = datetime.now().strftime("%Y-%b-%d_%H-%M-%S")
        d = datetime.now().strftime("%Y-%b-%d")
        d2 = datetime.now().strftime("%Y-%b")
        directory = '/var/pynetflow/logs/'+d2+'/'+d
        if not os.path.exists(directory):
            os.makedirs(directory)
        filename=directory+'/a'+dateTag
        f = open(filename,'w')
        timestamp = newTimestamp
        firstRun=0
    data,addr = UDPSock.recvfrom(4*1024) 
    if not data: 
        print "No header_data." 
        break 
    else: 
			header_data=data[0:20]
			netflow_header={ 
							'version': unpack('>h',header_data[0:2])[0],
							'count': unpack('>h',header_data[2:4])[0],
							'sys_uptime' : unpack('>i',header_data[4:8])[0],
							'unix_seconds' : unpack('>i',header_data[8:12])[0],
							'package_sequence':unpack('>i',header_data[12:16])[0],
							'source_id':unpack('>i',header_data[16:20])[0]}
			skipbytes=20
			templateid=unpack('>h',data[skipbytes:skipbytes+2])[0]
			datalength=unpack('>h',data[skipbytes+2:skipbytes+4])[0]
			if (templateid>=256):
				offset=skipbytes+4
				#counter += 1
				while (offset<=datalength-4):
#					netflow_record={  
#									'timestamp': netflow_header['unix_seconds'],
#									'source': addr[0],
#									'ipv4_src': inet_ntoa(pack('>L',unpack('>I',data[offset:offset+4])[0])),
#									'nat_ipv4_src': inet_ntoa(pack('>L',unpack('>I',data[offset+4:offset+8])[0])),
#									'ipv4_dst': inet_ntoa(pack('>L',unpack('>I',data[offset+8:offset+12])[0])),
#									'nat_ipv4_dst': inet_ntoa(pack('>L',unpack('>I',data[offset+12:offset+16])[0])),
#									'srcport': unpack('>H',data[offset+16:offset+18])[0],
#									'nat_srcport': unpack('>H',data[offset+18:offset+20])[0],
#									'dstport': unpack('>H',data[offset+20:offset+22])[0],
#									'nat_dstport': unpack('>H',data[offset+22:offset+24])[0],
#									'ingressVRFID': unpack('>L',data[offset+24:offset+28])[0],
#									'proto':unpack('>B',data[offset+28:offset+29])[0] ,
#									'natEvent':unpack('>B',data[offset+29:offset+30])[0] }
#					print binascii.hexlify(data[offset:offset+38])
					netflow_record={
                                                                        'sa': inet_ntoa(pack('>L',unpack('>I',data[offset:offset+4])[0])),
                                                                        'nat_sa': inet_ntoa(pack('>L',unpack('>I',data[offset+4:offset+8])[0])),
                                                                        'E':unpack('>B',data[offset+29:offset+30])[0],
									'ts':unpack('>Q',data[offset+30:offset+38])[0] }
					#if (netflow_record['proto']==0)and(netflow_record['da']=='0.0.0.0'):
					netflow_record['ts'] = datetime.fromtimestamp(netflow_record['ts']/1000).\
								replace(microsecond = (netflow_record['ts'] % 1000) * 1000)
					print >>f,netflow_record['ts'],netflow_record['E'],\
						netflow_record['sa'],netflow_record['nat_sa']
					records.insert(netflow_record)	
					offset += 38
UDPSock.close() 
