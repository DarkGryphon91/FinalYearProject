import Tkinter, tkFileDialog
import subprocess, time
import crypt, sys, string, random, re, urllib, urllib2, zipfile, hashlib
import socket, time, os, pygeoip, dpkt
from struct import *
from Tkinter import *
import pyPdf, sys, zipfile, struct
import PIL
import xml.dom.minidom as xmlDOM
import xml.etree.ElementTree as ET 
from pyPdf import PdfFileReader
from PIL import Image
from PIL.ExifTags import TAGS
from hachoir_metadata import metadata
from hachoir_core.cmd_line import unicodeFilename
from hachoir_parser import createParser

class switch(object):
    def __init__(self, value):
        self.value = value
        self.fall = False

    def __iter__(self):
        """Return the match method once, then stop"""
        yield self.match
        raise StopIteration
    
    def match(self, *args):
        """Indicate whether or not to enter a case suite"""
        if self.fall or not args:
            return True
        elif self.value in args: # changed for v1.5, see below
            self.fall = True
            return True
        else:
            return False

class ftgui(Tkinter.Tk):
   file_path=" "
   def __init__(self, parent):
	Tkinter.Tk.__init__(self, parent)
	self.parent=parent
	self.initialise()

   def initialise(self):
	self.grid()

	#self.entryVariable=Tkinter.StringVar()
	#self.entry=Tkinter.Entry(self, textvariable=self.entryVariable, width=100)
	#self.entry.grid(column=0, row=0, sticky='EW')
	#self.entryVariable.set(u"Please choose a file")
	self.filetextbox=Tkinter.Text(self, height=1)
	self.filetextbox.insert(END, "Please choose a file.")
	self.filetextbox.grid(column=0, row=0)

	filebutton=Tkinter.Button(self, text=u"Choose File", command=self.OnButtonClick)
	filebutton.grid(column=1, row=0)

	#self.labelVariable=Tkinter.StringVar()
	#label=Tkinter.Label(self, textvariable=self.labelVariable, height=15, anchor="w", fg="black", bg="white", wraplength=450)
	#label.grid(column=0, row=1, columnspan=2, sticky='EW')
	#self.labelVariable.set(u"Metadate is displayed here.")

	scrollbar=Tkinter.Scrollbar(self)
	self.textbox=Tkinter.Text(self)
	scrollbar.config(command=self.textbox.yview)
	self.textbox.config(yscrollcommand=scrollbar.set)
	self.textbox.insert(END, "Metadata is displayed here.")
	self.textbox.grid(column=0, row=1, columnspan=2)#, rowspan=2)

	extractbutton=Tkinter.Button(self, text=u"Extract", command=self.extract)
	extractbutton.grid(column=2, row=2)

   def OnButtonClick(self):
	global file_path
	file_path=tkFileDialog.askopenfilename()
	#self.entryVariable.set(file_path)
	self.filetextbox.delete(1.0, Tkinter.END)
	self.filetextbox.insert(Tkinter.END, file_path)
	self.filetextbox.update_idletasks()

   def extract(self):
	self.textbox.delete(1.0, Tkinter.END)
	self.textbox.update_idletasks()
	file_type=file_path.split('.')[1]
	for case in switch(file_type):
       	    if case('pdf'):
	      print "You chose to retrieve PDF metadata."
	      fileName=file_path
	      pdfFile = PdfFileReader(file(fileName, 'rb')) 
	      docInfo = pdfFile.getDocumentInfo()
	      pdfMeta='[*] PDF MetaData For: ' + str(fileName)+"\n"
	      for metaItem in docInfo:
		  pdfMeta+="[+] "+metaItem+": "+docInfo[metaItem]+"\n"
	      #self.labelVariable.set(pdfMeta)
	      
	      self.textbox.insert(END, pdfMeta)
	      self.textbox.update_idletasks()
	      break
            if case('mp4'):
	      print "You chose to retrieve Video File metadata."
	      filename = file_path
	      filename, realname = unicodeFilename(filename), filename
	      parser = createParser(filename)
	      vidMeta="[*] Video MetaData For: "+file_path+"\n"
	      for k,v in metadata.extractMetadata(parser)._Metadata__data.iteritems():
	         if v.values:
                    #print v.key, v.values[0].value
		    vidMeta+="[+] "+str(v.key)+": "+str(v.values[0].value)+"\n"
	      #self.labelVariable.set(vidMeta)
	      self.textbox.insert(END, vidMeta)
	      self.textbox.update_idletasks()
	      break
            if case('jpg') or case('JPG'):
	      print "You chose to retrieve Image File metadata."
	      imgFileName=file_path
	      immetfile=open("imageMetadata.txt", "w+")
	      for (k,v) in Image.open(imgFileName)._getexif().iteritems():
		  immet='%s = %s'%(TAGS.get(k), v)
		  immetfile.write(immet+'\n')
	      #self.labelVariable.set("The metadata for this file can be found in: imageMetadata.txt")
	      self.textbox.insert(END, "The metadata for this file can be found in: imageMetadata.txt")
	      self.textbox.update_idletasks()
	      break
            if case('mp3'):
	      print "You chose to retrieve Audio File metadata."
	      afile=file_path
	      audiofile=open(afile, "rb")
	      mdfile=open("audioMetadata.txt", "w+")
	      print "Decoding mp3 file"
	      md=audiofile.read(1500)
	      metad=repr(md)
	      audMeta="[*] Audio MetaData For: "+file_path+"\n"
	      mp3TagList={"AENC":"Audio Encryption", "APIC":"Attached Picture", "COMM":"Comments", "COMR":"Commercial Frame", "ENCR":"Encryption method registration", "EQUA":"Equalisation", "ETCO":"Event timing codes", "GEOB":"General Encapsulated Object", "GRID":"Group Identification Registration", "IPLS":"Involoved People list", "LINK":"Linked Information", "MCDI":"Music CD Identifier", "MLLT":"MPEG Location Lookup Table", "OWNE":"Ownership Frame", "PRIV":"Private Frame", "PCNT":"Play COunter", "POPM":"Popularimeter", "POSS":"Position Synchronisation Frame", "RBUF":"Recommended Buffer Size", "RVAD":"Relative Volume Adjustment", "RVRB":"Reverb", "SYLT":"Synchronised Lyric/Text", "SYTC":"Synchronised Tempo Codes", "TALB":"Album", "TBPM":"Beats Per Minute", "TCOM":"Composer", "TCON":"Content Type", "TCOP":"Copyright Message", "TDAT":"Date", "TDLY":"Playlist Delay", "TENC":"Encoded By", "TEXT":"Lyricist/Text Writer", "TFLT":"File Type", "TIME":"Time", "TIT1":"Content Group Description", "TIT2":"Title", "TIT3":"Subtitle", "TKEY":"Initial Key", "TLAN":"Language", "TLEN":"Length", "TMED":"Media Type", "TOAL":"Original Album", "TOFN":"Original Filename", "TOLY":"Original Lyricist/Text Writer", "TOPE":"Original Artist", "TORY":"Original Release Year", "TOWN":"File Owner", "TPE1":"Lead Performer", "TPE2":"Band Accompaniment", "TPE3":"Conductor", "TPE4":"Interpreted By", "TPOS":"Part of a Set", "TPUB":"Publisher", "TRCK":"Track Number", "TRDA":"Recording Dates", "TRSN":"Internet Radio Station Name", "TRSO":"Internet Radio Station Owner", "TSIZ":"Size", "TSRC":"International Standard Recording Code", "TSSE":"Software/Hardware and settings used for encoding", "TYER":"Year", "TXXX":"User defined test information frame", "UFID":"Unique File Indentifier", "USER":"Terms of Use", "USLT":"Unsynchronised Lyric Transcription", "WCOM":"Commercial Information", "WCOP":"Copyright Information", "WOAF":"Official audio file webpage", "WOAR":"Official artist/performer webpage", "WOAS":"Official audio source webpage", "WORS":"Official internet radio station homepage", "WPAY":"Payment", "WPUB":"Publishers official webpage", "WXXX":"User defined URL link frame"}
	      byteList=["\\x00","\\x01","\\x02","\\x03","\\x04","\\x05","\\x06","\\x07",
	  	     "\\x08","\\x09","\\x0a","\\x0b","\\x0c","\\x0d","\\x0e","\\x0f"]
	      for byte in byteList:
   		  metad=metad.replace(byte, '')
	      for tag,meaning in mp3TagList.iteritems():
   		  tagPos=metad.find(tag)
   		  if tagPos>0:
		      metad=metad[:tagPos]+'\n'+metad[tagPos:]
		      metad=metad.replace(tag, meaning)
	      mdfile.write(metad)	
	      #self.labelVariable.set("The metadata for this file can be found in: audioMetadata.txt")
	      self.textbox.insert(END, metad)
	      #self.textbox.insert(END, "The metadata for this file can be found in: audioMetadata.txt")
	      self.textbox.update_idletasks()
	      break
            if case('docx') or case('pptx') or case('xlsx'):
	      print "You chose to retrieve Microsoft Office Documents metadata."
	      docfile=file_path
	      zfile=zipfile.ZipFile(docfile)
	      xml=ET.XML(zfile.read('docProps/core.xml'))
	      xml=ET.tostring(xml)
	      xml=xmlDOM.parseString(xml)
	      docMeta=xml.toprettyxml()
	      #self.labelVariable.set(docMeta)
	      self.textbox.insert(END, docMeta)
	      self.textbox.update_idletasks()
	      break

class nmGUI(Tkinter.Tk):
   start=""
   def __init__(self, parent):
	Tkinter.Tk.__init__(self, parent)
	self.parent=parent
	self.initialise()

   
   def initialise(self):
	self.grid()

	self.scanvar = Tkinter.StringVar()
	# initial value
	self.scanvar.set('Please choose the scan type')
	choices = ['Quick', 'Full']
	option = Tkinter.OptionMenu(self, self.scanvar, *choices)
	option.grid(column=0, row=0)

	startbutton=Tkinter.Button(self, text=u"Start", command=self.OnStart)
	startbutton.grid(column=0, row=2)
	
	stopbutton=Tkinter.Button(self, text=u"Stop", command=self.OnStop)
	stopbutton.grid(column=1, row=2)

	self.labelVariable=Tkinter.StringVar()
	label=Tkinter.Label(self, textvariable=self.labelVariable, anchor="w", fg="black", bg="white")
	label.grid(column=0, row=1, columnspan=2, sticky='EW')
	self.labelVariable.set(u"Network Scanning results go here")

	scrollbar=Tkinter.Scrollbar(self)
	self.textbox=Tkinter.Text(self)#, height=4, width=50)
	scrollbar.config(command=self.textbox.yview)
	self.textbox.config(yscrollcommand=scrollbar.set)
	self.textbox.grid(column=0, row=3)

	#self.scan()

   def OnStart(self):
	global start
	start=True
	self.scan()

   def OnStop(self):
	global start
	start=False

   def scan(self):
	try:
   	    s=socket.socket( socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
	except socket.error, msg:
	    errormsg='Socket could not be created. Error Code: '+str(msg[0])+'Message'+str(msg[1])
	    self.textbox.insert(Tkinter.END, errormsg)
	    self.textbox.update_idletasks()
	    return
   	    #print 'Socket could not be created. Error Code: '+str(msg[0])+'Message'+str(msg[1])
   	    #sys.exit()
	#scanType=raw_input("Would you like to perform a quick or a full scan? ")
	if self.scanvar.get()=="Quick":
	   output="You chose a quick scan"
	   self.textbox.insert(Tkinter.END, output)
	   self.textbox.update_idletasks()
   	   maxPort=1024
	elif self.scanvar.get()=="Full":
	   output="You chose a full scan"
	   self.textbox.insert(Tkinter.END, output)
	   self.textbox.update_idletasks()
   	   maxPort=65535

        previousip=[] 
	while start:
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
              if s_addr!='127.0.0.1':
          	  if s_addr not in previousip:
	       	     output='\nTTL: '+str(ttl)+' IP Address: '+s_addr+' Packet Size: ' +str(len(packet))
		     previousip.append(s_addr)
	             if ttl==64:
	           	output+= '\n Operating System: Linux'
                     elif ttl==128:
	           	output+= '\n Operating System: Windows'
	       	     elif ttl==255:
		        output+= '\n Operating System: Mac/Cisco'
	             for port in range(1, maxPort):
                        try:
		            sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.connect((s_addr, port))
		            sock.send('Scanning for open ports\n')
		            result=sock.recv(100)
		            output+= '\n\t%d/tcp open'% port
		            output+= '\n\t'+str(results)
	                except:
		      	    pass
			
	   	  self.textbox.insert(Tkinter.END, output)
	   	  self.textbox.update_idletasks()

class psGUI(Tkinter.Tk):
   packets=" "
   ipLocations=" "
   downloads=" "
   attacks=" "
   def __init__(self, parent):
	Tkinter.Tk.__init__(self, parent)
	self.parent=parent
	self.initialise()

   def initialise(self):
	self.grid()

	packetbutton=Tkinter.Button(self, text=u"Packets", command=self.OnPacket)
	packetbutton.grid(column=0, row=1)
	
	ipbutton=Tkinter.Button(self, text=u"IP Locations", command=self.OnIP)
	ipbutton.grid(column=1, row=1)

	downloadbutton=Tkinter.Button(self, text=u"Downloads", command=self.OnDownload)
	downloadbutton.grid(column=2, row=1)
	
	attackbutton=Tkinter.Button(self, text=u"Attacks", command=self.OnAttack)
	attackbutton.grid(column=3, row=1)

	startbutton=Tkinter.Button(self, text=u"Start", command=self.OnStart)
	startbutton.grid(column=1, row=3)
	
	stopbutton=Tkinter.Button(self, text=u"Stop", command=self.OnStop)
	stopbutton.grid(column=2, row=3)
	
	scrollbar=Tkinter.Scrollbar(self)
	self.textbox=Tkinter.Text(self, width=150)
	scrollbar.config(command=self.textbox.yview)
	self.textbox.config(yscrollcommand=scrollbar.set)
	self.textbox.grid(column=0, row=2, columnspan=4)

   def OnStart(self):
	global ipLocations
	ipLocations="Starting packet sniffing.\n"
	global downloads
	downloads="Starting packet sniffing.\n"
	global attacks
	attacks="Starting packet sniffing.\n"
	#Convert a string of 6 characters of ethernet address into a dash separated hex string
	def eth_addr (a) :
  	   b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  	   return b
 
	#create a AF_PACKET type raw socket 
	#define ETH_P_ALL    0x0003          /* Every packet */
	try:
    	   s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
	except socket.error , msg:
	   errormsg='Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	   self.textbox.insert(Tkinter.END, errormsg)
	   self.textbox.update_idletasks()
	   return
    	   #print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    	   #sys.exit()

	timestr=time.strftime("%Y%m%d-%H%M%S")
	os.mkdir(timestr)
	pfile=open('%s/packets.txt' % timestr, 'w+')
	lfile=open('%s/ipLocations.txt' % timestr, 'w+') 
	dfile=open('%s/downloaded.txt' % timestr, 'w+')
	afile=open('%s/attackList.txt' % timestr, 'w+')
	locate=pygeoip.GeoIP('GeoLiteCity.dat')
	# receive a packet
	while True:
	    packet = s.recvfrom(65565)
     
	    #packet string from tuple
	    packet = packet[0]
     
	    #parse ethernet header
	    eth_length = 14
     
	    eth_header = packet[:eth_length]
	    eth = unpack('!6s6sH' , eth_header)
	    eth_protocol = socket.ntohs(eth[2])
	    print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
	    first='Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
	    pfile.write(''+first);
	    global packets
	    packets=first
	    #Parse IP packets, IP Protocol number = 8
	    if eth_protocol == 8 :
	        #Parse IP header
	        #take first 20 characters for the ip header
	        ip_header = packet[eth_length:20+eth_length]
         
	        #now unpack them
	        iph = unpack('!BBHHHBBH4s4s' , ip_header)
	 
	        version_ihl = iph[0]
	        version = version_ihl >> 4
	        ihl = version_ihl & 0xF
	 
	        iph_length = ihl * 4
	 
	        ttl = iph[5]
	        protocol = iph[6]
	        s_addr = socket.inet_ntoa(iph[8]);
	        d_addr = socket.inet_ntoa(iph[9]);
 
	        print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
	        second=' Version : '+str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' +str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + 'Destination Address : '+str(d_addr)
		pfile.write(''+second)
		packets+=second
		print''+str(s_addr)
		if (s_addr!='127.0.0.1'):
		   s_data = locate.record_by_name(s_addr)
		   d_data = locate.record_by_name(d_addr)
		   print ''+str(s_data)
	 	   print ''+str(d_data)
		   if (s_data):
		      s_city = s_data['city']
		      s_country = s_data['country_name']
		      slocation=' Source IP Address : ' + str(s_addr) + ' Source City : ' +str(s_city) + ' Source Country : ' + str(s_country)
		      lfile.write(''+slocation)
		     # global ipLocations
		      ipLocations+=slocation
		   elif (d_data):
		        d_country = d_data['country_name']
		        d_city = d_data['city']
		        dlocation= ' Destination IP Address : ' + str(d_addr) + ' Destination City : ' + str(d_city) + ' Destination Country : ' + str(d_country) + '\n'
		  	lfile.write(''+dlocation)
		       # global ipLocations
		        ipLocations+=dlocation
		   else:  
		      s_city='Unavailable'
		      s_Country='Unavailable'
		      d_City='Unavailable'
		      d_Country='Unavailable'
		      location=' Source IP Address : ' + str(s_addr) + ' Source City : ' +str(s_city) + ' Source Country : ' + str(s_country) + ' Destination IP Address : ' + str(d_addr) + ' Destination City : ' + str(d_city) + ' Destination COuntry : ' + str(d_country) + '\n'
	              lfile.write(''+location)
		     # global ipLocations
		      ipLocations+=location
	        #TCP protocol
	        if protocol == 6 :
	            t = iph_length + eth_length
	            tcp_header = packet[t:t+20]
	 
	            #now unpack them
	            tcph = unpack('!HHLLBBHHH' , tcp_header)
             
	            source_port = tcph[0]
	            dest_port = tcph[1]
	            sequence = tcph[2]
	            acknowledgement = tcph[3]
	            doff_reserved = tcph[4]
	            tcph_length = doff_reserved >> 4
	             
	            print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
	            third='Source Port : ' + str(source_port) + 'Destination Port : ' + str(dest_port) + 'Sequence Number : ' + str(sequence) + 'Acknowledgement : ' + str(acknowledgement) + 'TCP Header Length : '+str(tcph_length) 
	            pfile.write(''+third)
		    packets+=third
		    h_size = eth_length + iph_length + tcph_length * 4
	            data_size = len(packet) - h_size
             
	            #get data from the packet
	            data = packet[h_size:]
             
	            print 'Data : ' + data
		    fourth='Data : ' + data + '\n'
		    pfile.write(''+fourth)
		    packets+=fourth
		    try:
	               http=dpkt.http.Request(''+data)
		       print ''+str(http)
		       print 'Before Get if statement'
		       if (http.method=='GET'):
		           print 'Inside Get if statement'
		           uri=http.uri.lower()
		           print ''+str(uri)
		           if '.zip' in uri and 'loic' in uri:
		             downloaded= 'IP Address : ' + str(s_addr) + ' Downloaded Loic\n'
		             dfile.write(''+downloaded)
			     downloads+=downloaded
	            except:
			pass
		    try:
		       http=dpkt.http.Request(''+data)
		       if (dest_port ==6667):
			  if ('!lazor' in data):
			     attack='DDOS Hivemind issued by : ' + str(s_addr) + '\n'
			     afile.write(''+attack)
			     attacks+=attack
		       elif (source_port ==6667):
			   if ('!lazor' in data):
			      attack='DDOS Hivemind isued to : ' + str(s_addr) + '\n'
			      afile.write(''+attack)
			      attacks+=attack
		    except:
			pass
	        #ICMP Packets
	        elif protocol == 1 :
	            u = iph_length + eth_length
	            icmph_length = 4
	            icmp_header = packet[u:u+4]
 
	            #now unpack them :)
	            icmph = unpack('!BBH' , icmp_header)
	             
	            icmp_type = icmph[0]
	            code = icmph[1]
	            checksum = icmph[2]
	             
	            print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
	            fifth='TYpe : ' + str(icmp_type) + ' COde : ' + str(code) + 'Checksum : ' + str(checksum) 
	            pfile.write(''+fifth)
		    packets+=fifth

		    h_size = eth_length + iph_length + icmph_length
	            data_size = len(packet) - h_size
             
	            #get data from the packet
	            data = packet[h_size:]
             
	            print 'Data : ' + data
		    sixth='Data : ' + data + '\n'
		    pfile.write(''+sixth)
		    packets+=sixth
	    
	        #UDP packets
	        elif protocol == 17 :
	            u = iph_length + eth_length
	            udph_length = 8
	            udp_header = packet[u:u+8]
 
	            #now unpack them 
	            udph = unpack('!HHHH' , udp_header)
             
	            source_port = udph[0]
	            dest_port = udph[1]
	            length = udph[2]
	            checksum = udph[3]
             
	            print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
		    seventh='Source Port : ' + str(source_port) + 'Destination Port : ' + str(dest_port) + 'Length : ' + str(length) + 'Checksum : ' + str(checksum)             
	            pfile.write(''+seventh)
		    packets+=seventh
		    h_size = eth_length + iph_length + udph_length
	            data_size = len(packet) - h_size
             
	            #get data from the packet
	            data = packet[h_size:]
             
	            print 'Data : ' + data
		    eigth='Data : ' + data + '\n'
		    pfile.write(''+eigth)
		    packets+=eigth
	    
	        #some other IP packet like IGMP
	        else :
	            print 'Protocol other than TCP/UDP/ICMP'
             
	        print
		self.textbox.insert(Tkinter.END, packets)
		self.textbox.update_idletasks()

   def OnStop(self):
	pass

   def OnPacket(self):
	global packets
	self.textbox.delete(1.0, Tkinter.END)
	self.textbox.update_idletasks()
	self.textbox.insert(Tkinter.END, packets)
	self.textbox.update_idletasks()

   def OnIP(self):
	global ipLocations
	self.textbox.delete(1.0, Tkinter.END)
	self.textbox.update_idletasks()
	self.textbox.insert(Tkinter.END, ipLocations)
	self.textbox.update_idletasks()

   def OnDownload(self):
	global downloads
	self.textbox.delete(1.0, Tkinter.END)
	self.textbox.update_idletasks()
	self.textbox.insert(Tkinter.END, downloads)
	self.textbox.update_idletasks()

   def OnAttack(self):
	global attacks
	self.textbox.delete(1.0, Tkinter.END)
	self.textbox.update_idletasks()
	self.textbox.insert(Tkinter.END, attacks)
	self.textbox.update_idletasks()


class pcGUI(Tkinter.Tk):
   #file_path=" "
   def __init__(self, parent):
	Tkinter.Tk.__init__(self, parent)
	self.parent=parent
	self.initialise()

   def initialise(self):
	self.grid()

	userButton=Tkinter.Button(self, text=u"User Password", command=self.crackUser)
	userButton.grid(column=0, row=0)

	zipButton=Tkinter.Button(self, text=u"Zip File", command=self.crackZip)
	zipButton.grid(column=1, row=0)

	websiteButton=Tkinter.Button(self, text=u"Website Password", command=self.crackWebsite)
	websiteButton.grid(column=0, row=1)

	wordButton=Tkinter.Button(self, text=u"Generate Word List", command=self.generateWordList)
	wordButton.grid(column=1, row=1)

   def crackUser(self):
	def OnUserButtonClick():
		global user_file_path
		user_file_path=tkFileDialog.askopenfilename()
		#userentryVariable.set(user_file_path)
		usertextbox.delete(1.0, Tkinter.END)
		usertextbox.insert(Tkinter.END, user_file_path)
		usertextbox.update_idletasks()

	def OnWordButtonClick():
		global word_file_path
		word_file_path=tkFileDialog.askopenfilename()
		#wordentryVariable.set(word_file_path)
		wordtextbox.delete(1.0, Tkinter.END)
		wordtextbox.insert(Tkinter.END, word_file_path)
		wordtextbox.update_idletasks()

	def OnCrack():
		pfile=user_file_path
	   	dfile=word_file_path
	   	osystem=ostextbox.get(1.0, Tkinter.END)
		osystem=osystem.replace('\n', '')
	   	passfile=open(pfile, "r")
	   	dictfile=open(dfile, "r")
		result=" "
	
	   	if osystem=="Linux" or osystem=="linux":
	      	   for line in passfile.readlines():
	         	if ":" in line:
		    	   user=line.split(':')[0]
		    	   password=line.split(':')[1].strip(' ')
		    	   salt=password.split('$')[2]
		    	   salt="$6$"+salt
		    	   print "Cracking password for: "+user
	           	for word in dictfile.readlines():
   	            	   word=word.replace('\n', '')
	            	   encryptedword=crypt.crypt(word, salt)
	            	   if (encryptedword == password):
	               	      result+="Found password for "+user+": "+word+"\n"
		              dictfile.seek(0)
	   	if osystem=="Windows" or osystem=="windows":
	      	   for line in passfile.readlines():
		   	if ":" in line:
		      	   user=line.split(':')[0]
		      	   password=line.split(':')[4].strip('\n')
		   	   for word in dictfile.readlines():
		      		word=word.replace('\n', '')
		      		encryptedWord=hashlib.new('md4', word.encode('utf-16le')).hexdigest()
		      	   	if (encryptedWord == password):
			   	   result+="Found password for "+user+": "+word+"\n"
			   	   dictfile.seek(0)
		#labelVariable.set(result)
		textbox.delete(1.0, Tkinter.END)
		textbox.insert(Tkinter.END, result)
		textbox.update_idletasks()
	print "Crack User"
	userInterface=Tkinter.Toplevel(self)
	userInterface.grid()
	userInterface.wm_title("Crack User Password")

	#userentryVariable=Tkinter.StringVar()
	#userentry=Tkinter.Entry(userInterface, textvariable=userentryVariable, width=50)
	#userentry.grid(column=0, row=0, sticky='EW')
	#userentryVariable.set(u"Please choose a file containing encrypted user details")
	usertextbox=Tkinter.Text(userInterface, height=1)
	usertextbox.insert(END, "Please choose a file containing encrypted user details")
	usertextbox.grid(column=0, row=0)

	ufilebutton=Tkinter.Button(userInterface, text=u"Choose File", command=OnUserButtonClick)
	ufilebutton.grid(column=1, row=0)

	#wordentryVariable=Tkinter.StringVar()
	#wordentry=Tkinter.Entry(userInterface, textvariable=wordentryVariable, width=50)
	#wordentry.grid(column=0, row=1, sticky='EW')
	#wordentryVariable.set(u"Please choose a word list")
	wordtextbox=Tkinter.Text(userInterface, height=1)
	wordtextbox.insert(END, "Please choose a word list")
	wordtextbox.grid(column=0, row=1)

	wfilebutton=Tkinter.Button(userInterface, text=u"Choose File", command=OnWordButtonClick)
	wfilebutton.grid(column=1, row=1)

	#osentryVariable=Tkinter.StringVar()
	#osentry=Tkinter.Entry(userInterface, textvariable=osentryVariable, width=50)
	#osentry.grid(column=0, row=2, sticky='EW')
	#osentryVariable.set(u"Please enter user's operating system")
	ostextbox=Tkinter.Text(userInterface, height=1)
	ostextbox.insert(END, "Please enter user's operating system")
	ostextbox.grid(column=0, row=2)
	
	textbox=Tkinter.Text(userInterface)
	textbox.insert(END, "Cracked Password goes here.")
	textbox.grid(column=0, row=3)
	#labelVariable=Tkinter.StringVar()
	#label=Tkinter.Label(userInterface, textvariable=labelVariable, height=20, anchor="w", fg="black", bg="white")
	#label.grid(column=0, row=3, columnspan=2, sticky='EW')
	#labelVariable.set(u"Cracked Password goes here.")

	crackButton=Tkinter.Button(userInterface, text=u"Crack", command=OnCrack)
	crackButton.grid(column=0, row=4)

   def crackZip(self):
	def OnZipButtonClick():
		global zip_file_path
		zip_file_path=tkFileDialog.askopenfilename()
		#fileentryVariable.set(zip_file_path)
		filetextbox.delete(1.0, Tkinter.END)
		filetextbox.insert(Tkinter.END, zip_file_path)
		filetextbox.update_idletasks()

	def OnWordButtonClick():
		global word_file_path
		word_file_path=tkFileDialog.askopenfilename()
		#wordentryVariable.set(word_file_path)
		wordtextbox.delete(1.0, Tkinter.END)
		wordtextbox.insert(Tkinter.END, word_file_path)
		wordtextbox.update_idletasks()

	def onCrack():
		specfile=zip_file_path
   		specpassfile=word_file_path
   		zFile=zipfile.ZipFile(specfile)
   		passFile=open(specpassfile, "r")
   		for line in passFile.readlines():
      		    password=line.strip('\n')
      		    try:
	   		zFile.extractall(pwd=password)
			#labelVariable.set("Password: "+password)
			textbox.delete(1.0, Tkinter.END)
			textbox.insert(Tkinter.END, "Password: "+password)
			textbox.update_idletasks()
      		    except Exception, e:
	   		pass
	print "Crack Zip file"
	zipInterface=Tkinter.Toplevel(self)
	zipInterface.grid()
	zipInterface.wm_title("Crack Zip File Password")

	filetextbox=Tkinter.Text(zipInterface, height=1)
	filetextbox.insert(END, "Please choose a zip file")
	filetextbox.grid(column=0, row=0)
	#fileentryVariable=Tkinter.StringVar()
	#fileentry=Tkinter.Entry(zipInterface, textvariable=fileentryVariable, width=50)
	#fileentry.grid(column=0, row=0, sticky='EW')
	#fileentryVariable.set(u"Please choose a zip file")

	zfilebutton=Tkinter.Button(zipInterface, text=u"Choose File", command=OnZipButtonClick)
	zfilebutton.grid(column=1, row=0)

	wordtextbox=Tkinter.Text(zipInterface, height=1)
	wordtextbox.insert(END, "Please choose a word list")
	wordtextbox.grid(column=0, row=1)
	#wordentryVariable=Tkinter.StringVar()
	#wordentry=Tkinter.Entry(zipInterface, textvariable=wordentryVariable, width=50)
	#wordentry.grid(column=0, row=1, sticky='EW')
	#wordentryVariable.set(u"Please choose a word list")

	wfilebutton=Tkinter.Button(zipInterface, text=u"Choose File", command=OnWordButtonClick)
	wfilebutton.grid(column=1, row=1)

	textbox=Tkinter.Text(zipInterface)
	textbox.insert(END, "Cracked Password goes here.")
	textbox.grid(column=0, row=2)
	#labelVariable=Tkinter.StringVar()
	#label=Tkinter.Label(zipInterface, textvariable=labelVariable, anchor="w", fg="black", bg="white")
	#label.grid(column=0, row=2, columnspan=2, sticky='EW')
	#labelVariable.set(u"Cracked Password goes here.")

	crackButton=Tkinter.Button(zipInterface, text=u"Crack", command=onCrack)
	crackButton.grid(column=0, row=3)
	

   def crackWebsite(self):
	def OnWordButtonClick():
		global word_file_path
		word_file_path=tkFileDialog.askopenfilename()
		#wordentryVariable.set(word_file_path)
		wordtextbox.delete(1.0, Tkinter.END)
		wordtextbox.insert(Tkinter.END, word_file_path)
		wordtextbox.update_idletasks()
	
	def OnCrack():
		host=webtextbox.get(1.0, Tkinter.END).replace('\n', '')
	   	usr=usertextbox.get(1.0, Tkinter.END).replace('\n', '')
	   	website=urllib2.HTTPHandler(host)
	   	wl=word_file_path
	   	badLogin=errorvar.get()
	   	words=open(wl, "r").readlines()
	   	print "Words loaded: ", len(words)
	
	   	for word in words:
	      	   word=word.replace("\n","")
	      	   loginSequence=[('username',usr),('password',word)]
	      	   loginData=urllib.urlencode(loginSequence)
	      	   opener=urllib2.build_opener(website)
	      	   opener.addheaders=[('User-agent', 'Mozilla/5.0')]
	      	   source=opener.open(host,loginData).read()
	      	   if re.search(badLogin,source)==None:
		  	#labelVariable.set("Successful Login: ",usr, word)
			textbox.delete(1.0, Tkinter.END)
			textbox.insert(Tkinter.END, "Successful Login: "+usr+" "+word)
			textbox.update_idletasks()

	print "Crack website"
	webInterface=Tkinter.Toplevel(self)
	webInterface.grid()
	webInterface.wm_title("Crack Website Password")

	wordtextbox=Tkinter.Text(webInterface, height=1)
	wordtextbox.insert(END, "Please choose a word list")
	wordtextbox.grid(column=0, row=1)
	#wordentryVariable=Tkinter.StringVar()
	#wordentry=Tkinter.Entry(webInterface, textvariable=wordentryVariable, width=50)
	#wordentry.grid(column=0, row=1, sticky='EW')
	#wordentryVariable.set(u"Please choose a word list")

	wfilebutton=Tkinter.Button(webInterface, text=u"Choose File", command=OnWordButtonClick)
	wfilebutton.grid(column=1, row=1)
	
	webtextbox=Tkinter.Text(webInterface, height=1)
	webtextbox.insert(END, "Please enter login url or website")
	webtextbox.grid(column=0, row=2)
	#webentryVariable=Tkinter.StringVar()
	#webentry=Tkinter.Entry(webInterface, textvariable=webentryVariable, width=50)
	#webentry.grid(column=0, row=2, sticky='EW')
	#webentryVariable.set(u"Please enter login url of website")

	usertextbox=Tkinter.Text(webInterface, height=1)
	usertextbox.insert(END, "Please enter the username")
	usertextbox.grid(column=0, row=3)
	#userentryVariable=Tkinter.StringVar()
	#userentry=Tkinter.Entry(webInterface, textvariable=userentryVariable, width=50)
	#userentry.grid(column=0, row=3, sticky='EW')
	#userentryVariable.set(u"Please enter the username")

	errorvar = Tkinter.StringVar()
	# initial value
	errorvar.set('Please choose the login error')
	choices = ['error_invalid_auth']
	option = Tkinter.OptionMenu(webInterface, errorvar, *choices)
	option.grid(column=0, row=4)

	textbox=Tkinter.Text(webInterface)
	textbox.insert(END, "Cracked Password goes here.")
	textbox.grid(column=0, row=5)
	#labelVariable=Tkinter.StringVar()
	#label=Tkinter.Label(webInterface, textvariable=labelVariable, anchor="w", fg="black", bg="white")
	#label.grid(column=0, row=5, columnspan=2, sticky='EW')
	#labelVariable.set(u"Cracked Password goes here.")

	crackButton=Tkinter.Button(webInterface, text=u"Crack", command=OnCrack)
	crackButton.grid(column=0, row=6)

   def generateWordList(self):
	def generate():
	   minimum=int(mintextbox.get(1.0, Tkinter.END).replace('\n', ''))
	   maximum=int(maxtextbox.get(1.0, Tkinter.END).replace('\n', ''))
	   wordMax=int(counttextbox.get(1.0, Tkinter.END).replace('\n', ''))
	
	   alphabet=string.letters[0:52]+string.digits+string.punctuation
	   word=''
	   wordlist=open("wordlist.txt", "w+")
	   for count in xrange(0, wordMax):
	       for x in random.sample(alphabet, random.randint(minimum, maximum)):
		    word+=x
	       wordlist.write(word+'\n')
	       word=''
	   wordlist.close()

	print "Generate word list"
	wordInterface=Tkinter.Toplevel(self)
	wordInterface.grid()
	wordInterface.wm_title("Generate Word List")

	mintextbox=Tkinter.Text(wordInterface, height=1)
	mintextbox.insert(END, "Enter minimum word length here")
	mintextbox.grid(column=0, row=0)	
	#minentryVariable=Tkinter.StringVar()
	#minentry=Tkinter.Entry(wordInterface, textvariable=minentryVariable, width=30)
	#minentry.grid(column=0, row=0, sticky='EW')
	#minentryVariable.set(u"Enter minimum word length here")

	maxtextbox=Tkinter.Text(wordInterface, height=1)
	maxtextbox.insert(END, "Enter the maximum word length here")
	maxtextbox.grid(column=0, row=1)
	#maxentryVariable=Tkinter.StringVar()
	#maxentry=Tkinter.Entry(wordInterface, textvariable=maxentryVariable, width=30)
	#maxentry.grid(column=0, row=1, sticky='EW')
	#maxentryVariable.set(u"Enter maximum word length here")

	counttextbox=Tkinter.Text(wordInterface, height=1)
	counttextbox.insert(END, "Enter number of words here")
	counttextbox.grid(column=0, row=2)
	#countentryVariable=Tkinter.StringVar()
	#countentry=Tkinter.Entry(wordInterface, textvariable=countentryVariable, width=30)
	#countentry.grid(column=0, row=2, sticky='EW')
	#countentryVariable.set(u"Enter number of words here")

	button=Tkinter.Button(wordInterface, text=u"Generate", command=generate)
	button.grid(column=0, row=3)

class wcGUI(Tkinter.Tk):
   def __init__(self, parent):
	Tkinter.Tk.__init__(self, parent)
	self.parent=parent
	self.initialise()

   def initialise(self):
	self.grid()

	scrollbar=Tkinter.Scrollbar(self)
	self.textbox=Tkinter.Text(self)
	scrollbar.config(command=self.textbox.yview)
	self.textbox.config(yscrollcommand=scrollbar.set)
	self.textbox.grid(column=0, row=0, rowspan=2)

	scanbutton=Tkinter.Button(self, text=u"Scan", command=self.OnScan)
	scanbutton.grid(column=1, row=0)

	crackbutton=Tkinter.Button(self, text=u"Crack", command=self.OnCrack)
	crackbutton.grid(column=1, row=1)

   def OnScan(self):
	command=['iwlist', 'wlan0', 'scan']
	output=subprocess.Popen(command, stdout=subprocess.PIPE).stdout.readlines()
	data=[]
	wifiFile=open("wifiReport.txt", "w+")

	for item in output:
	   wifiFile.write(item)
	self.textbox.insert(Tkinter.END, "The results of the scan can be found in: wifiReport.txt")
	self.textbox.update_idletasks()

   def OnCrack(self):
	def OnCrackButtonClick():
		ssid=ssidtextbox.get(1.0, Tkinter.END).replace('\n', '')
		apmac=mactextbox.get(1.0, Tkinter.END).replace('\n', '')
		channel=channeltextbox.get(1.0, Tkinter.END).replace('\n', '')
		interface=interfacetextbox.get(1.0, Tkinter.END).replace('\n', '')
		passfile=wordtextbox.get(1.0, Tkinter.END).replace('\n', '')
	
		airodumpcmd=['airodump-ng','-w psk',interface]
		airodumpout=subprocess.Popen(airodumpcmd, shell=True)
		time.sleep(10)
		aircrackcmd=['aircrack-ng','-w'+passfile,'-b'+apmac,' psk*.cap']
		aircrackout=subprocess.Popen(aircrackcmd, stdout=subprocess.PIPE).stdout.readlines()
		
		for item in aircrackout:
		   item=item.strip()
		   keyPos=item.find("KEY FOUND:")
		   if keyPos>0:
			key=item[keyPos]
		   else:
			key="Key not found."
		
		self.textbox.insert(Tkinter.END, ""+ssid+": "+key)
		self.textbox.update_idletasks()
		dialogueInterface.destroy()

	def OnWordButtonClick():
		global word_file_path
		word_file_path=tkFileDialog.askopenfilename()
		#wordentryVariable.set(word_file_path)
		wordtextbox.delete(1.0, Tkinter.END)
		wordtextbox.insert(Tkinter.END, word_file_path)
		wordtextbox.update_idletasks()

	dialogueInterface=Tkinter.Toplevel(self)
	dialogueInterface.grid()
	dialogueInterface.wm_title("Crack Wireless Dialogue Box")

	ssidtextbox=Tkinter.Text(dialogueInterface, height=1)
	ssidtextbox.insert(END, "Please enter the SSID")
	ssidtextbox.grid(column=0, row=0)
	#ssidVariable=Tkinter.StringVar()
	#ssid=Tkinter.Entry(dialogueInterface, textvariable=ssidVariable, width=50)
	#ssid.grid(column=0, row=0, sticky='EW')
	#ssidVariable.set(u"Please enter the SSID")

	mactextbox=Tkinter.Text(dialogueInterface, height=1)
	mactextbox.insert(END, "Please enter the MAC address")
	mactextbox.grid(column=0, row=1)
	#macVariable=Tkinter.StringVar()
	#mac=Tkinter.Entry(dialogueInterface, textvariable=macVariable, width=50)
	#mac.grid(column=0, row=1, sticky='EW')
	#macVariable.set(u"Please enter the MAC")

	wordtextbox=Tkinter.Text(dialogueInterface, height=1)
	wordtextbox.insert(END, "Please choose a word list")
	wordtextbox.grid(column=0, row=2)
	#wordentryVariable=Tkinter.StringVar()
	#wordentry=Tkinter.Entry(dialogueInterface, textvariable=wordentryVariable, width=50)
	#wordentry.grid(column=0, row=2, sticky='EW')
	#wordentryVariable.set(u"Please choose a word list")

	wfilebutton=Tkinter.Button(dialogueInterface, text=u"Choose File", command=OnWordButtonClick)
	wfilebutton.grid(column=1, row=2)

	channeltextbox=Tkinter.Text(dialogueInterface, height=1)
	channeltextbox.insert(END, "Please enter the channel number")
	channeltextbox.grid(column=0, row=3)
	#channelVariable=Tkinter.StringVar()
	#channel=Tkinter.Entry(dialogueInterface, textvariable=channelVariable)
	#channel.grid(column=0, row=3, sticky='EW')
	#channelVariable.set(u"Please enter the channel number")

	interfacetextbox=Tkinter.Text(dialogueInterface, height=1)
	interfacetextbox.insert(END, "Please enter the wireless interface name")
	interfacetextbox.grid(column=0, row=4)
	#interfaceVariable=Tkinter.StringVar()
	#interface=Tkinter.Entry(dialogueInterface, textvariable=interfaceVariable)
	#interface.grid(column=0, row=4, sticky='EW')
	#interfaceVariable.set(u"Please enter the wireless interface name")

	crackbutton=Tkinter.Button(dialogueInterface, text=u"Crack", command=OnCrackButtonClick)
	crackbutton.grid(column=0, row=5)

class Hydra(Tkinter.Tk):
   def __init__(self, parent):
	Tkinter.Tk.__init__(self, parent)
	self.parent=parent
	self.initialise()

   def initialise(self):
	self.grid()
	
	wirelessbutton=Tkinter.Button(self, text=u"Wireless Cracker", command=self.OnWireless)
	wirelessbutton.grid(column=0, row=0)

	networkbutton=Tkinter.Button(self, text=u"Network Miner", command=self.OnNetwork)
	networkbutton.grid(column=2, row=0)

	passwordbutton=Tkinter.Button(self, text=u"Password Cracker", command=self.OnPassword)
	passwordbutton.grid(column=1, row=1)

	forensicbutton=Tkinter.Button(self, text=u"Forensic Tool", command=self.OnForensic)
	forensicbutton.grid(column=0, row=2)

	packetbutton=Tkinter.Button(self, text=u"Packet Sniffer", command=self.OnPacket)
	packetbutton.grid(column=2, row=2)

   def OnWireless(self):
	app=wcGUI(None)
   	app.title('Wireless Cracker')
   	app.mainloop()

   def OnNetwork(self):
	app=nmGUI(None)
	app.title('Network Miner')
	app.mainloop()

   def OnPassword(self):
	app=pcGUI(None)
   	app.title('Password Cracker')
   	app.mainloop()

   def OnForensic(self):
	app=ftgui(None)
	app.title('Forensic Tool')
	app.mainloop()

   def OnPacket(self):
	app=psGUI(None)
   	app.title('Packet Sniffer')
   	app.mainloop()

if __name__=="__main__":
   app=Hydra(None)
   app.title('Hydra')
   app.mainloop()
