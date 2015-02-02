#!/usr/bin/python2

import socket, sys
from struct import *

try:
   s=socket.socket( socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except socket.error, msg:
   print 'Socket could not be created. Error COde: '+str(msg[0])+'Message'+str(msg[1])
   sys.exit()

lowip=raw_input("Enter the lowest IP Address of the range you wish to scan: ")
highip=raw_input("Enter the highest IP Address of the range you wish to scan: ")
lowip=lowip.replace('.', '')
print ''+str(lowip)
highip=highip.replace('.', '')
print ''+str(highip)
exists=False
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
       if int(s_addr2) in range(int(lowip), int(highip)) and s_addr!='127.0.0.1':
          if not s_addr in previousip and not exists:
	       print 'TTL: '+str(ttl)+' IP Address: '+s_addr+' Packet Size: ' +str(len(packet))
               previousip=[s_addr]
	       exists=True
	       if ttl==64:
	           print ' Operating System: Linux'
               elif ttl==128:
	           print ' Operating System: Windows'
	       for port in range(1, 65535):
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
      
