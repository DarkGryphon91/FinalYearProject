#!/usr/bin/python2

import socket, sys
from struct import *

try:
   s=socket.socket( socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except socket.error, msg:
   print 'Socket could not be created. Error Code: '+str(msg[0])+'Message'+str(msg[1])
   sys.exit()

scanType=raw_input("Would you like to perform a quick or a full scan? ")
if scanType=="quick" or scanType=="Quick":
   maxPort=1024
elif scanType=="full" or scanType=="Full":
   maxPort=65535

exists=False
previousip=set()
while True:
   packet=s.recvfrom(65565)
   packet =packet[0]
   eth_length=14
   eth_header=packet[:eth_length]
   eth=unpack('!6s6sH', eth_header)
   eth_protocol=socket.ntohs(eth[2])
   
   if eth_protocol == 8:
       ip_header=packet[eth_length:20+eth_length]
       iph=unpack('!BBHHHBBH4s4s', ip_header)
       ttl=iph[5]
       s_addr=socket.inet_ntoa(iph[8])
       s_addr=str(s_addr)
       s_addr2=s_addr.replace('.', '')
       previousip=list() 
       if s_addr!='127.0.0.1':
          if s_addr not in previousip and not exists:
	       print 'TTL: '+str(ttl)+' IP Address: '+s_addr+' Packet Size: ' +str(len(packet))
               #previousip=[s_addr]
	       #list(set(previousip))
	      # exists=True
	       if ttl==64:
	           print ' Operating System: Linux'
               elif ttl==128:
	           print ' Operating System: Windows'
	       elif ttl==255:
		   print ' Operating System: Mac/Cisco'
	       for port in range(1, maxPort):
                   try:
		      sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                      sock.connect((s_addr, port))
		      sock.send('Scanning for open ports\n')
		      result=sock.recv(100)
		      print '\t%d/tcp open'% port
		      print '\t'+str(results)
	           except:
		      pass
       previousip=[s_addr]
       list(set(previousip))
      
