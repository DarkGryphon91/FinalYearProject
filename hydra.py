#Hydra Source Code written by Niall Caffrey C11508443 DT211/4 Dublin Institute of Technology
#This program has been divided into classes. Each class serves a different function.
#The classes are as follows:
#psGUI-Packet Sniffer GUI
#nmGUI-Network Miner GUI
#pcGUI-Password Cracker GUI
#ftGUI-Forensic Tool GUI
#wcGUI-Wireless Cracker GUI
#hydra-Base System GUI

#Imports for libraries needed for code
import Tkinter, tkFileDialog #GUI Libraries
import subprocess, time #Wireless Cracker Libraries
import crypt, sys, string, random, re, urllib, urllib2, zipfile, hashlib #Forensic Tool Libraries
import socket, time, os, pygeoip, dpkt #Packet Sniffer Libraries
from struct import * #Packet Sniffer Libraries
from Tkinter import * #GUI Libraries
import pyPdf, sys, zipfile, struct #Forensic Tool Libraries
import PIL #Forensic Tool Libraries
import xml.dom.minidom as xmlDOM #Forensic Tool Libraries
import xml.etree.ElementTree as ET  #Forensic Tool Libraries
from pyPdf import PdfFileReader #Forensic Tool Libraries
from PIL import Image #Forensic Tool Libraries
from PIL.ExifTags import TAGS #Forensic Tool Libraries
from hachoir_metadata import metadata #Forensic Tool Libraries
from hachoir_core.cmd_line import unicodeFilename #Forensic Tool Libraries
from hachoir_parser import createParser #Forensic Tool Libraries

#class used to give a similar functionality to case statement
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
        elif self.value in args: 
            self.fall = True
            return True
        else:
            return False

#Forensic Tool Class
class ftGUI(Tkinter.Tk):
   file_path=" " #Global variable to hold file path
   #Function declaring initial GUI
   def __init__(self, parent):
	Tkinter.Tk.__init__(self, parent)
	self.parent=parent
	self.initialise()

	#Function initialising GUI
   def initialise(self):
	self.grid() #Setting the GUI to use a grid layout

	#defining the text box for the file path
	self.filetextbox=Tkinter.Text(self, height=1)
	self.filetextbox.insert(END, "Please choose a file.")
	self.filetextbox.grid(column=0, row=0)

	#defining a button for the file text box 
	filebutton=Tkinter.Button(self, text=u"Choose File", command=self.OnButtonClick)
	filebutton.grid(column=1, row=0)

	#defining a text box to hold the metadata being extracted, as well as making the text box scrollable
	scrollbar=Tkinter.Scrollbar(self)
	self.textbox=Tkinter.Text(self)
	scrollbar.config(command=self.textbox.yview)
	self.textbox.config(yscrollcommand=scrollbar.set)
	self.textbox.insert(END, "Metadata is displayed here.")
	self.textbox.grid(column=0, row=1, columnspan=2)

	#defining a button to begin the metadata extraction
	extractbutton=Tkinter.Button(self, text=u"Extract", command=self.extract)
	extractbutton.grid(column=2, row=2)

	#function to choose a file
   def OnButtonClick(self):
	global file_path #states that it's the global file_path variable that's about to be used
	file_path=tkFileDialog.askopenfilename() #opens a file dialogue box to choose a file
	#inserts the file_path into the file text box
	self.filetextbox.delete(1.0, Tkinter.END)
	self.filetextbox.insert(Tkinter.END, file_path)
	self.filetextbox.update_idletasks()

	#function to extract metadata
   def extract(self):
	self.textbox.delete(1.0, Tkinter.END)
	self.textbox.update_idletasks()
	file_type=file_path.split('.')[1] #splits the file path to determine what type of file was selected 
	for case in switch(file_type): #python version of case statement that switch class - created above - allows
			#if the file is a pdf do the following
       	    if case('pdf'): 
	      print "You chose to retrieve PDF metadata."
	      fileName=file_path
	      pdfFile = PdfFileReader(file(fileName, 'rb')) #opens the pdf file
	      docInfo = pdfFile.getDocumentInfo() #extracts document info for the pdf  
	      pdfMeta='[*] PDF MetaData For: ' + str(fileName)+"\n"
	      for metaItem in docInfo:
		  pdfMeta+="[+] "+metaItem+": "+docInfo[metaItem]+"\n"
	      #inserts the metadata into the text box
	      self.textbox.insert(END, pdfMeta)
	      self.textbox.update_idletasks()
	      break
			#if the file is a mp4 do the following
            if case('mp4'):
	      print "You chose to retrieve Video File metadata."
	      filename = file_path
	      filename, realname = unicodeFilename(filename), filename
	      parser = createParser(filename) #creates a parser for the mp4 file
	      vidMeta="[*] Video MetaData For: "+file_path+"\n"
	      for k,v in metadata.extractMetadata(parser)._Metadata__data.iteritems(): #extracts and iterates through the metadata of the mp4
	         if v.values:
		    vidMeta+="[+] "+str(v.key)+": "+str(v.values[0].value)+"\n"
			#inserts the metadata into the text box
	      self.textbox.insert(END, vidMeta)
	      self.textbox.update_idletasks()
	      break
			#if file is a jpeg do the following
            if case('jpg') or case('JPG'):
	      print "You chose to retrieve Image File metadata."
	      imgFileName=file_path
	      immetfile=open("imageMetadata.txt", "w+") #creates file to hold image metadata
	      for (k,v) in Image.open(imgFileName)._getexif().iteritems(): #extracts metadata and iterates through the metadata
		  immet='%s = %s'%(TAGS.get(k), v)
		  immetfile.write(immet+'\n') #writes metadata to the file created above
	      self.textbox.insert(END, "The metadata for this file can be found in: imageMetadata.txt")
	      self.textbox.update_idletasks()
	      break
		    #if file is a mp3 do the following
            if case('mp3'):
	      print "You chose to retrieve Audio File metadata."
	      afile=file_path
	      audiofile=open(afile, "rb") #open mp3 in raw binary format
	      mdfile=open("audioMetadata.txt", "w+") #create a file to hold audio metadata
	      print "Decoding mp3 file"
	      md=audiofile.read(1500) #reads in first 1500 bytes in audio file 
	      metad=repr(md) #creates a string representation of the raw binary
	      audMeta="[*] Audio MetaData For: "+file_path+"\n"
		  #specifies the mp3 metadata tags and their meaning and list of bytes to be removed
	      mp3TagList={"AENC":"Audio Encryption", "APIC":"Attached Picture", "COMM":"Comments", "COMR":"Commercial Frame", "ENCR":"Encryption method registration", "EQUA":"Equalisation", "ETCO":"Event timing codes", "GEOB":"General Encapsulated Object", "GRID":"Group Identification Registration", "IPLS":"Involoved People list", "LINK":"Linked Information", "MCDI":"Music CD Identifier", "MLLT":"MPEG Location Lookup Table", "OWNE":"Ownership Frame", "PRIV":"Private Frame", "PCNT":"Play COunter", "POPM":"Popularimeter", "POSS":"Position Synchronisation Frame", "RBUF":"Recommended Buffer Size", "RVAD":"Relative Volume Adjustment", "RVRB":"Reverb", "SYLT":"Synchronised Lyric/Text", "SYTC":"Synchronised Tempo Codes", "TALB":"Album", "TBPM":"Beats Per Minute", "TCOM":"Composer", "TCON":"Content Type", "TCOP":"Copyright Message", "TDAT":"Date", "TDLY":"Playlist Delay", "TENC":"Encoded By", "TEXT":"Lyricist/Text Writer", "TFLT":"File Type", "TIME":"Time", "TIT1":"Content Group Description", "TIT2":"Title", "TIT3":"Subtitle", "TKEY":"Initial Key", "TLAN":"Language", "TLEN":"Length", "TMED":"Media Type", "TOAL":"Original Album", "TOFN":"Original Filename", "TOLY":"Original Lyricist/Text Writer", "TOPE":"Original Artist", "TORY":"Original Release Year", "TOWN":"File Owner", "TPE1":"Lead Performer", "TPE2":"Band Accompaniment", "TPE3":"Conductor", "TPE4":"Interpreted By", "TPOS":"Part of a Set", "TPUB":"Publisher", "TRCK":"Track Number", "TRDA":"Recording Dates", "TRSN":"Internet Radio Station Name", "TRSO":"Internet Radio Station Owner", "TSIZ":"Size", "TSRC":"International Standard Recording Code", "TSSE":"Software/Hardware and settings used for encoding", "TYER":"Year", "TXXX":"User defined test information frame", "UFID":"Unique File Indentifier", "USER":"Terms of Use", "USLT":"Unsynchronised Lyric Transcription", "WCOM":"Commercial Information", "WCOP":"Copyright Information", "WOAF":"Official audio file webpage", "WOAR":"Official artist/performer webpage", "WOAS":"Official audio source webpage", "WORS":"Official internet radio station homepage", "WPAY":"Payment", "WPUB":"Publishers official webpage", "WXXX":"User defined URL link frame"}
	      byteList=["\\x00","\\x01","\\x02","\\x03","\\x04","\\x05","\\x06","\\x07",
	  	     "\\x08","\\x09","\\x0a","\\x0b","\\x0c","\\x0d","\\x0e","\\x0f"]
			 #iterates through metadata removing the bytes specified above
	      for byte in byteList:
   		  metad=metad.replace(byte, '')
		  #iterates through list of tags specified above  
	      for tag,meaning in mp3TagList.iteritems():
   		  tagPos=metad.find(tag) #looks for tags specified above
   		  if tagPos>0: #if tag is found
		      metad=metad[:tagPos]+'\n'+metad[tagPos:] #places a new line just before the tag's position in file
		      metad=metad.replace(tag, meaning) #replaces the tag with it's associated meaning
	      mdfile.write(metad)	#writes metadata to the file created above
		  #inserts metadata into text box
	      self.textbox.insert(END, metad)
	      self.textbox.update_idletasks()
	      break
		  #if file is a microsoft office document do the following
            if case('docx') or case('pptx') or case('xlsx'):
	      print "You chose to retrieve Microsoft Office Documents metadata."
	      docfile=file_path
	      zfile=zipfile.ZipFile(docfile) #open document as a zip file
	      xml=ET.XML(zfile.read('docProps/core.xml')) #convert the contents of core.xml into xml
	      xml=ET.tostring(xml) #turn xml into a string
		  #pretty print the xml i.e. each tag on a new line and tabbed in
	      xml=xmlDOM.parseString(xml)
	      docMeta=xml.toprettyxml()
		  #insert metadata into text box
	      self.textbox.insert(END, docMeta)
	      self.textbox.update_idletasks()
	      break
		  
#Network Miner Class
class nmGUI(Tkinter.Tk):
   start=""
   #function declaring initial GUI
   def __init__(self, parent):
	Tkinter.Tk.__init__(self, parent)
	self.parent=parent
	self.initialise()

   #function initialising GUI
   def initialise(self):
	self.grid() #setting the GUI to use grid layout

	#declaring a drop down menu to choose scan type
	self.scanvar = Tkinter.StringVar()
	self.scanvar.set('Please choose the scan type')
	choices = ['Quick', 'Full']
	option = Tkinter.OptionMenu(self, self.scanvar, *choices)
	option.grid(column=0, row=0)

	#declaring start button to begin scanning
	startbutton=Tkinter.Button(self, text=u"Start", command=self.OnStart)
	startbutton.grid(column=0, row=2)
	
	#declaring stop button to end scanning
	stopbutton=Tkinter.Button(self, text=u"Stop", command=self.OnStop)
	stopbutton.grid(column=1, row=2)

	self.labelVariable=Tkinter.StringVar()
	label=Tkinter.Label(self, textvariable=self.labelVariable, anchor="w", fg="black", bg="white")
	label.grid(column=0, row=1, columnspan=2, sticky='EW')
	self.labelVariable.set(u"Network Scanning results go here")

	#declaring a scrollable text box to hold results
	scrollbar=Tkinter.Scrollbar(self)
	self.textbox=Tkinter.Text(self)
	scrollbar.config(command=self.textbox.yview)
	self.textbox.config(yscrollcommand=scrollbar.set)
	self.textbox.grid(column=0, row=3)

	#function to start scanning
   def OnStart(self):
	global start
	start=True
	self.scan()

	#function to stop scanning
   def OnStop(self):
	global start
	start=False

	#function to scan the network
   def scan(self):
   #tries to create a socket and inserts error message into text box if it fails
	try:
   	    s=socket.socket( socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
	except socket.error, msg:
	    errormsg='Socket could not be created. Error Code: '+str(msg[0])+'Message'+str(msg[1])
	    self.textbox.insert(Tkinter.END, errormsg)
	    self.textbox.update_idletasks()
	    return
	#sets number of ports depending on the type of scan quick/full
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

        previousip=[] #creates list to hold all IP addresses that appear on network
	while start:
   	   packet=s.recvfrom(65565) #scans packets on network
	   #unpacks packets into a form that the program can interpret
   	   packet =packet[0]
   	   eth_length=14
   	   eth_header=packet[:eth_length]
    	   eth=unpack('!6s6sH', eth_header)
   	   eth_protocol=socket.ntohs(eth[2])
   
   	   if eth_protocol == 8: #checks if the protocol used is TCP
       	      ip_header=packet[eth_length:20+eth_length]
       	      iph=unpack('!BBHHHBBH4s4s', ip_header) #unpacks the ip header
              ttl=iph[5]
              s_addr=socket.inet_ntoa(iph[8]) #retrieves the source address
              s_addr=str(s_addr)
              s_addr2=s_addr.replace('.', '')
			  #checks to see if the source address is home
              if s_addr!='127.0.0.1':
          	  if s_addr not in previousip: #checks to see if the IP address has already appeared on the network
	       	     output='\nTTL: '+str(ttl)+' IP Address: '+s_addr+' Packet Size: ' +str(len(packet)) 
		     previousip.append(s_addr) #adds IP address to list of those that have already appeared
			 #if the ttl value is 64 then the machine that sent it was a Linux machine
	             if ttl==64:
	           	output+= '\n Operating System: Linux'
				#if the ttl value is 128 then the machine that sent it was a Windows machine
                     elif ttl==128:
	           	output+= '\n Operating System: Windows'
				#if the ttl value is 255 then the machine that sent it was a Mac/Cisco machine
	       	     elif ttl==255:
		        output+= '\n Operating System: Mac/Cisco'
	             for port in range(1, maxPort):
				 #tries to connect to the ports on the machine and prints the port number if it succeeded
                        try:
		            sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.connect((s_addr, port))
		            sock.send('Scanning for open ports\n')
		            result=sock.recv(100)
		            output+= '\n\t%d/tcp open'% port
		            output+= '\n\t'+str(results)
	                except:
		      	    pass
			#inserts results into the text box
	   	  self.textbox.insert(Tkinter.END, output)
	   	  self.textbox.update_idletasks()

#Packet Sniffer Class
class psGUI(Tkinter.Tk):
   packets=" " #global variable to hold packets
   ipLocations=" " #global variable to hold IP locations 
   downloads=" " #global variable to hold download list
   attacks=" " #global variable to hold list of attackers
   #function to define GUI
   def __init__(self, parent):
	Tkinter.Tk.__init__(self, parent)
	self.parent=parent
	self.initialise()

	#function to initialise GUI
   def initialise(self):
	self.grid() #sets GUI to use a grid layout

	#defines a packet button
	packetbutton=Tkinter.Button(self, text=u"Packets", command=self.OnPacket)
	packetbutton.grid(column=0, row=1)
	
	#defines an IP locations button
	ipbutton=Tkinter.Button(self, text=u"IP Locations", command=self.OnIP)
	ipbutton.grid(column=1, row=1)

	#defines a downloads button
	downloadbutton=Tkinter.Button(self, text=u"Downloads", command=self.OnDownload)
	downloadbutton.grid(column=2, row=1)
	
	#defines an attacks button
	attackbutton=Tkinter.Button(self, text=u"Attacks", command=self.OnAttack)
	attackbutton.grid(column=3, row=1)

	#defines a start button 
	startbutton=Tkinter.Button(self, text=u"Start", command=self.OnStart)
	startbutton.grid(column=1, row=3)
	
	#defines a stop button
	stopbutton=Tkinter.Button(self, text=u"Stop", command=self.OnStop)
	stopbutton.grid(column=2, row=3)
	
	#defines a scrollable text box to hold results
	scrollbar=Tkinter.Scrollbar(self)
	self.textbox=Tkinter.Text(self, width=150)
	scrollbar.config(command=self.textbox.yview)
	self.textbox.config(yscrollcommand=scrollbar.set)
	self.textbox.grid(column=0, row=2, columnspan=4)

	#function to scan the network
   def OnStart(self):
   #declares that the global ipLocations, downloads and attacks variables will be used
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
 
 #tries to create a socket and inserts the possible error message into the text box
	try:
    	   s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
	except socket.error , msg:
	   errormsg='Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	   self.textbox.insert(Tkinter.END, errormsg)
	   self.textbox.update_idletasks()
	   return

	timestr=time.strftime("%Y%m%d-%H%M%S") 	   #gets current date and time in a certain format
	os.mkdir(timestr) #creates a folder that's called the time
	pfile=open('%s/packets.txt' % timestr, 'w+') #creates file to hold packets
	lfile=open('%s/ipLocations.txt' % timestr, 'w+') #creates file to hold IP locations
	dfile=open('%s/downloaded.txt' % timestr, 'w+') #creates file to hold downloaded list
	afile=open('%s/attackList.txt' % timestr, 'w+') #creates file to hold attack list
	locate=pygeoip.GeoIP('GeoLiteCity.dat') #loads in file containing the geographical locations of IP addresses
	# receive a packet
	while True:
	    packet = s.recvfrom(65565)
     
	    packet = packet[0]
     
	    #parse ethernet header
	    eth_length = 14
     
	 #unpack the packet header received
	    eth_header = packet[:eth_length]
	    eth = unpack('!6s6sH' , eth_header)
	    eth_protocol = socket.ntohs(eth[2])
	    print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
	    first='Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
	    pfile.write(''+first); #writes the first part of packet to file
	    global packets
	    packets=first #sets global packet variable to contain first part of packet
	    #Parse IP packets, IP Protocol number = 8
	    if eth_protocol == 8 :
	        #Parse IP header
	        #take first 20 characters for the ip header
	        ip_header = packet[eth_length:20+eth_length]
         
	        #unpack them
	        iph = unpack('!BBHHHBBH4s4s' , ip_header)
	 
	        version_ihl = iph[0]
	        version = version_ihl >> 4
	        ihl = version_ihl & 0xF
	 
	        iph_length = ihl * 4
	 
	        ttl = iph[5] #retrieves ttl value of packet
	        protocol = iph[6] #retrieves protocol number of packet
	        s_addr = socket.inet_ntoa(iph[8]); #retrieves source address of packet
	        d_addr = socket.inet_ntoa(iph[9]); #retrieves destination address of packet
 
	        print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
	        second=' Version : '+str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' +str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + 'Destination Address : '+str(d_addr)
		pfile.write(''+second) #writes second part of packet to file
		packets+=second #append the second part of the packet to global packet variable  
		print''+str(s_addr)
		if (s_addr!='127.0.0.1'):
		   s_data = locate.record_by_name(s_addr) #locate the related geographical location for the source address
		   d_data = locate.record_by_name(d_addr) #locate the related geographical location for the destination address
		   print ''+str(s_data)
	 	   print ''+str(d_data)
		   if (s_data): #if there's a source location
		      s_city = s_data['city']
		      s_country = s_data['country_name']
		      slocation=' Source IP Address : ' + str(s_addr) + ' Source City : ' +str(s_city) + ' Source Country : ' + str(s_country)
		      lfile.write(''+slocation) #write to file source location
		      ipLocations+=slocation #append to global variable ipLocations source location
		   elif (d_data): #if there's a destination location
		        d_country = d_data['country_name']
		        d_city = d_data['city']
		        dlocation= ' Destination IP Address : ' + str(d_addr) + ' Destination City : ' + str(d_city) + ' Destination Country : ' + str(d_country) + '\n'
		  	lfile.write(''+dlocation) #write to file destination location
		        ipLocations+=dlocation #append to global variable ipLocations destination location
		   else:  
		      s_city='Unavailable'
		      s_Country='Unavailable'
		      d_City='Unavailable'
		      d_Country='Unavailable'
		      location=' Source IP Address : ' + str(s_addr) + ' Source City : ' +str(s_city) + ' Source Country : ' + str(s_country) + ' Destination IP Address : ' + str(d_addr) + ' Destination City : ' + str(d_city) + ' Destination COuntry : ' + str(d_country) + '\n'
	              lfile.write(''+location)
		      ipLocations+=location
	        #check if the protocol is TCP
	        if protocol == 6 :
	            t = iph_length + eth_length
	            tcp_header = packet[t:t+20]
	 
	            #now unpack the header
	            tcph = unpack('!HHLLBBHHH' , tcp_header)
             
	            source_port = tcph[0] #retrieve the source port
	            dest_port = tcph[1] #retrieve the destination port
	            sequence = tcph[2] #retrieve the sequence number
	            acknowledgement = tcph[3] #retrieve the acknowledgement number
	            doff_reserved = tcph[4] #retrieve the reserved bits
	            tcph_length = doff_reserved >> 4
	             
	            print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length)
	            third='Source Port : ' + str(source_port) + 'Destination Port : ' + str(dest_port) + 'Sequence Number : ' + str(sequence) + 'Acknowledgement : ' + str(acknowledgement) + 'TCP Header Length : '+str(tcph_length) 
	            pfile.write(''+third) #write third part of packet to packets file
		    packets+=third #append third part of packet to global variable packets
			#calculate the size of the data
		    h_size = eth_length + iph_length + tcph_length * 4
	            data_size = len(packet) - h_size
             
	            #get data from the packet
	            data = packet[h_size:]
             
	            print 'Data : ' + data
		    fourth='Data : ' + data + '\n'
		    pfile.write(''+fourth) #write fourth part of packet to packets file
		    packets+=fourth #append fourth part of packet to global variable packets
		    try:
	               http=dpkt.http.Request(''+data) #gets http request from packet data
		       print ''+str(http)
		       print 'Before Get if statement'
		       if (http.method=='GET'): #checks if the http method was get
		           print 'Inside Get if statement'
		           uri=http.uri.lower()
		           print ''+str(uri)
		           if '.zip' in uri and 'loic' in uri: #checks if the packet was to download a program called loic
		             downloaded= 'IP Address : ' + str(s_addr) + ' Downloaded Loic\n'
		             dfile.write(''+downloaded) #writes the IP address of the person who downloaded loic to downloads file
			     downloads+=downloaded #appends IP address of the person who downloaded loic to global variable downloads
	            except:
			pass
		    try:
		       http=dpkt.http.Request(''+data) #gets http request from packet data
		       if (dest_port ==6667): #checks if the destination port of the packet was 6667
			  if ('!lazor' in data): #if the term "!lazor" was included in the packet data
			     attack='DDOS Hivemind issued by : ' + str(s_addr) + '\n'
			     afile.write(''+attack) #writes IP address of person who initiated a DDOS attack to attack file
			     attacks+=attack #appends IP address of person who initiated a DDOS attack to attack global variable
		       elif (source_port ==6667): #checks if source port of the packet was 6667
			   if ('!lazor' in data): 
			      attack='DDOS Hivemind isued to : ' + str(s_addr) + '\n'
			      afile.write(''+attack) #writes IP address of person who received the command to initiate DDOS attack to file
			      attacks+=attack #appends IP address of person who received the command to initiate DDOS attack to attacks global variable
		    except:
			pass
	        #checks if protocol was ICMP 
	        elif protocol == 1 :
				#defines the header
	            u = iph_length + eth_length
	            icmph_length = 4
	            icmp_header = packet[u:u+4]
 
	            #unpacks the header
	            icmph = unpack('!BBH' , icmp_header)
	             
	            icmp_type = icmph[0] #retrieves the icmp type
	            code = icmph[1] #retrieves the code number
	            checksum = icmph[2] #retrieves the checksum
	             
	            print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)
	            fifth='TYpe : ' + str(icmp_type) + ' COde : ' + str(code) + 'Checksum : ' + str(checksum) 
	            pfile.write(''+fifth) #writes fifth part of packets to packets file
		    packets+=fifth #appends fifth part of packets to packets global variable
			#defines the size of the data
		    h_size = eth_length + iph_length + icmph_length
	            data_size = len(packet) - h_size
             
	            #get data from the packet
	            data = packet[h_size:]
             
	            print 'Data : ' + data
		    sixth='Data : ' + data + '\n' 
		    pfile.write(''+sixth) #writes sixth part of packets to packets file
		    packets+=sixth #appends sixth part of packets to packets global variable
	    
	        #checks if the protocol was UDP 
	        elif protocol == 17 :
				#defines the header
	            u = iph_length + eth_length
	            udph_length = 8
	            udp_header = packet[u:u+8]
 
	            #unpacks the header
	            udph = unpack('!HHHH' , udp_header)
             
	            source_port = udph[0] #retrieves source port
	            dest_port = udph[1] #retrieves destination port
	            length = udph[2] #retrieves length 
	            checksum = udph[3] #retrieves checksum
             
	            print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
		    seventh='Source Port : ' + str(source_port) + 'Destination Port : ' + str(dest_port) + 'Length : ' + str(length) + 'Checksum : ' + str(checksum)             
	            pfile.write(''+seventh) #writes seventh part of packets to packets file
		    packets+=seventh #appends seventh part of packets to packets global variable
			#defines size of data
		    h_size = eth_length + iph_length + udph_length
	            data_size = len(packet) - h_size
             
	            #get data from the packet
	            data = packet[h_size:]
             
	            print 'Data : ' + data
		    eigth='Data : ' + data + '\n'
		    pfile.write(''+eigth) #writes eigth part of packets to packets file
		    packets+=eigth #appends eight part of packets to packets global variable
	    
	        #some other IP packet like IGMP
	        else :
	            print 'Protocol other than TCP/UDP/ICMP'
             
	        print
			#inserts packets variable into text box
		self.textbox.insert(Tkinter.END, packets)
		self.textbox.update_idletasks()

   def OnStop(self):
	pass

	#function that deletes contents of text box and replaces with contents of global variable packets
   def OnPacket(self):
	global packets
	self.textbox.delete(1.0, Tkinter.END)
	self.textbox.update_idletasks()
	self.textbox.insert(Tkinter.END, packets)
	self.textbox.update_idletasks()

	#function that deletes contents of text box and replaces with contents of global variable ipLocations
   def OnIP(self):
	global ipLocations
	self.textbox.delete(1.0, Tkinter.END)
	self.textbox.update_idletasks()
	self.textbox.insert(Tkinter.END, ipLocations)
	self.textbox.update_idletasks()

	#function that deletes contents of text box and replaces with contents of global variable downloads
   def OnDownload(self):
	global downloads
	self.textbox.delete(1.0, Tkinter.END)
	self.textbox.update_idletasks()
	self.textbox.insert(Tkinter.END, downloads)
	self.textbox.update_idletasks()

	#function that deletes contents of text box and replaces with contents of global variable attacks
   def OnAttack(self):
	global attacks
	self.textbox.delete(1.0, Tkinter.END)
	self.textbox.update_idletasks()
	self.textbox.insert(Tkinter.END, attacks)
	self.textbox.update_idletasks()

#Password Cracker Class
class pcGUI(Tkinter.Tk):
	#function to define initial GUI
   def __init__(self, parent):
	Tkinter.Tk.__init__(self, parent)
	self.parent=parent
	self.initialise()

	#function to initialise GUI
   def initialise(self):
	self.grid() #sets GUI to grid layout

	#defines a user password button
	userButton=Tkinter.Button(self, text=u"User Password", command=self.crackUser)
	userButton.grid(column=0, row=0)

	#defines a zip file button
	zipButton=Tkinter.Button(self, text=u"Zip File", command=self.crackZip)
	zipButton.grid(column=1, row=0)

	#defines a website password button
	websiteButton=Tkinter.Button(self, text=u"Website Password", command=self.crackWebsite)
	websiteButton.grid(column=0, row=1)

	#defines a generate word list button
	wordButton=Tkinter.Button(self, text=u"Generate Word List", command=self.generateWordList)
	wordButton.grid(column=1, row=1)

	#function that defines crack user password GUI and performs user password cracking
   def crackUser(self):
   #function that opens file dialogue box and inserts chosen file into user file path text box
	def OnUserButtonClick():
		global user_file_path
		user_file_path=tkFileDialog.askopenfilename()
		usertextbox.delete(1.0, Tkinter.END)
		usertextbox.insert(Tkinter.END, user_file_path)
		usertextbox.update_idletasks()
	#function that opens file dialogue box and inserts chosen file into word file path text box
	def OnWordButtonClick():
		global word_file_path
		word_file_path=tkFileDialog.askopenfilename()
		wordtextbox.delete(1.0, Tkinter.END)
		wordtextbox.insert(Tkinter.END, word_file_path)
		wordtextbox.update_idletasks()

	#function that performs user password cracking
	def OnCrack():
		pfile=user_file_path
	   	dfile=word_file_path
	   	osystem=ostextbox.get(1.0, Tkinter.END)
		osystem=osystem.replace('\n', '')
	   	passfile=open(pfile, "r") #opens user file
	   	dictfile=open(dfile, "r") #opens dictionary file
		result=" "
	
	   	if osystem=="Linux" or osystem=="linux": #checks if specified operating system is Linux
	      	   for line in passfile.readlines(): #reads in user file
	         	if ":" in line:
		    	   user=line.split(':')[0] #retrieves user name from user file
		    	   password=line.split(':')[1].strip(' ') #retrieves encrypted password from user file
		    	   salt=password.split('$')[2] #retrieves salt from user file
		    	   salt="$6$"+salt
		    	   print "Cracking password for: "+user
	           	for word in dictfile.readlines(): #reads in dictionary file
   	            	   word=word.replace('\n', '')
	            	   encryptedword=crypt.crypt(word, salt) #encrypts word in dictionary file using salt
	            	   if (encryptedword == password): #checks if encrypted word matches retrieved encrypted password
	               	      result+="Found password for "+user+": "+word+"\n" #appends result to result variable
		              dictfile.seek(0) #returns dictionary file to beginning
	   	if osystem=="Windows" or osystem=="windows": #checks if specified operating system is Windows
	      	   for line in passfile.readlines(): #reads in user file
		   	if ":" in line:
		      	   user=line.split(':')[0] #retrieves user name from user file
		      	   password=line.split(':')[4].strip('\n') #retrieves encrypted password from user file
		   	   for word in dictfile.readlines(): #reads in dictionary file
		      		word=word.replace('\n', '')
		      		encryptedWord=hashlib.new('md4', word.encode('utf-16le')).hexdigest() #encrypts word in dictionary file
		      	   	if (encryptedWord == password): #checks id encrypted word matches retrieved encrypted password
			   	   result+="Found password for "+user+": "+word+"\n" #appends result to result variable
			   	   dictfile.seek(0) #returns dictionary file to beginning
		#inserts results into text box
		textbox.delete(1.0, Tkinter.END)
		textbox.insert(Tkinter.END, result)
		textbox.update_idletasks()
	print "Crack User"
	#defines a new top level -a new window- for cracking user password
	userInterface=Tkinter.Toplevel(self)
	userInterface.grid()
	userInterface.wm_title("Crack User Password")

	#define a user file text box
	usertextbox=Tkinter.Text(userInterface, height=1)
	usertextbox.insert(END, "Please choose a file containing encrypted user details")
	usertextbox.grid(column=0, row=0)

	#defines a user file button
	ufilebutton=Tkinter.Button(userInterface, text=u"Choose File", command=OnUserButtonClick)
	ufilebutton.grid(column=1, row=0)

	#defines a word file text box
	wordtextbox=Tkinter.Text(userInterface, height=1)
	wordtextbox.insert(END, "Please choose a word list")
	wordtextbox.grid(column=0, row=1)

	#defines a word file button
	wfilebutton=Tkinter.Button(userInterface, text=u"Choose File", command=OnWordButtonClick)
	wfilebutton.grid(column=1, row=1)

	#defines an operating system text box
	ostextbox=Tkinter.Text(userInterface, height=1)
	ostextbox.insert(END, "Please enter user's operating system")
	ostextbox.grid(column=0, row=2)
	
	#defines a text box
	textbox=Tkinter.Text(userInterface)
	textbox.insert(END, "Cracked Password goes here.")
	textbox.grid(column=0, row=3)

	#defines a button to start the cracking
	crackButton=Tkinter.Button(userInterface, text=u"Crack", command=OnCrack)
	crackButton.grid(column=0, row=4)
	
	#function that defines crack zip password GUI and performs zip file cracking
   def crackZip(self):
   #function that opens file dialogue box and inserts chosen file into zip file text box
	def OnZipButtonClick():
		global zip_file_path
		zip_file_path=tkFileDialog.askopenfilename()
		filetextbox.delete(1.0, Tkinter.END)
		filetextbox.insert(Tkinter.END, zip_file_path)
		filetextbox.update_idletasks()

	#function that opens file dialogue box and inserts chosen file into word list text box
	def OnWordButtonClick():
		global word_file_path
		word_file_path=tkFileDialog.askopenfilename()
		wordtextbox.delete(1.0, Tkinter.END)
		wordtextbox.insert(Tkinter.END, word_file_path)
		wordtextbox.update_idletasks()

	#function that performs zip file cracking
	def onCrack():
		specfile=zip_file_path
   		specpassfile=word_file_path
   		zFile=zipfile.ZipFile(specfile) 
   		passFile=open(specpassfile, "r") #opens dictionary file
   		for line in passFile.readlines(): #reads in dictionary file
      		    password=line.strip('\n')
      		    try:
	   		zFile.extractall(pwd=password) #attempts to extract files from zip file using word from dictionary
			textbox.delete(1.0, Tkinter.END)
			textbox.insert(Tkinter.END, "Password: "+password) #inserts correct password into text box
			textbox.update_idletasks()
      		    except Exception, e:
	   		pass
	print "Crack Zip file"
	#defines a new top level-a new window- for cracking zip file password
	zipInterface=Tkinter.Toplevel(self)
	zipInterface.grid()
	zipInterface.wm_title("Crack Zip File Password")

	#defines zip file text box
	filetextbox=Tkinter.Text(zipInterface, height=1)
	filetextbox.insert(END, "Please choose a zip file")
	filetextbox.grid(column=0, row=0)

	#defines zip file button
	zfilebutton=Tkinter.Button(zipInterface, text=u"Choose File", command=OnZipButtonClick)
	zfilebutton.grid(column=1, row=0)

	#defines word list text box
	wordtextbox=Tkinter.Text(zipInterface, height=1)
	wordtextbox.insert(END, "Please choose a word list")
	wordtextbox.grid(column=0, row=1)

	#defines word list button
	wfilebutton=Tkinter.Button(zipInterface, text=u"Choose File", command=OnWordButtonClick)
	wfilebutton.grid(column=1, row=1)

	#defines text box
	textbox=Tkinter.Text(zipInterface)
	textbox.insert(END, "Cracked Password goes here.")
	textbox.grid(column=0, row=2)

	#defines button to start cracking
	crackButton=Tkinter.Button(zipInterface, text=u"Crack", command=onCrack)
	crackButton.grid(column=0, row=3)
	
   #function that defines website cracking GUI and performs website cracking
   def crackWebsite(self):
   #function that opens file dialogue box, inserts chosen word list into word list text box
	def OnWordButtonClick():
		global word_file_path
		word_file_path=tkFileDialog.askopenfilename()
		wordtextbox.delete(1.0, Tkinter.END)
		wordtextbox.insert(Tkinter.END, word_file_path)
		wordtextbox.update_idletasks()
	
	#function that performs website cracking
	def OnCrack():
		host=webtextbox.get(1.0, Tkinter.END).replace('\n', '') 
	   	usr=usertextbox.get(1.0, Tkinter.END).replace('\n', '')
	   	website=urllib2.HTTPHandler(host) #creates a http handler for specified website
	   	wl=word_file_path
	   	badLogin=errorvar.get()
	   	words=open(wl, "r").readlines() #opens and reads in dictionary file
	   	print "Words loaded: ", len(words)
	
	   	for word in words:
	      	   word=word.replace("\n","")
	      	   loginSequence=[('username',usr),('password',word)] #specifies login details for website
	      	   loginData=urllib.urlencode(loginSequence) #encodes login details for use in http
	      	   opener=urllib2.build_opener(website) #builds an opener for specified website-allows website to be opened and used
	      	   opener.addheaders=[('User-agent', 'Mozilla/5.0')] #adds a header to make website think that login request is coming from Firefox
	      	   source=opener.open(host,loginData).read() #attempts to login in to website
	      	   if re.search(badLogin,source)==None: #checks if the bad login error was returned
			   #inserts results into text box
			textbox.delete(1.0, Tkinter.END)
			textbox.insert(Tkinter.END, "Successful Login: "+usr+" "+word)
			textbox.update_idletasks()

	print "Crack website"
	#defines a new top level-a new window- for website cracking
	webInterface=Tkinter.Toplevel(self)
	webInterface.grid()
	webInterface.wm_title("Crack Website Password")

	#defines word list text box
	wordtextbox=Tkinter.Text(webInterface, height=1)
	wordtextbox.insert(END, "Please choose a word list")
	wordtextbox.grid(column=0, row=1)

	#defines word list button
	wfilebutton=Tkinter.Button(webInterface, text=u"Choose File", command=OnWordButtonClick)
	wfilebutton.grid(column=1, row=1)
	
	#defines website text box
	webtextbox=Tkinter.Text(webInterface, height=1)
	webtextbox.insert(END, "Please enter login url or website")
	webtextbox.grid(column=0, row=2)

	#defines username text box
	usertextbox=Tkinter.Text(webInterface, height=1)
	usertextbox.insert(END, "Please enter the username")
	usertextbox.grid(column=0, row=3)

	#defiens drop down menu for choosing bad login error
	errorvar = Tkinter.StringVar()
	errorvar.set('Please choose the login error')
	choices = ['error_invalid_auth']
	option = Tkinter.OptionMenu(webInterface, errorvar, *choices)
	option.grid(column=0, row=4)

	#defines text box
	textbox=Tkinter.Text(webInterface)
	textbox.insert(END, "Cracked Password goes here.")
	textbox.grid(column=0, row=5)

	#defines button for starting the cracking
	crackButton=Tkinter.Button(webInterface, text=u"Crack", command=OnCrack)
	crackButton.grid(column=0, row=6)

	#function that defines word list generator GUI and generates word list
   def generateWordList(self):
   #function that generates word list
	def generate():
	   minimum=int(mintextbox.get(1.0, Tkinter.END).replace('\n', ''))
	   maximum=int(maxtextbox.get(1.0, Tkinter.END).replace('\n', ''))
	   wordMax=int(counttextbox.get(1.0, Tkinter.END).replace('\n', ''))
	
	   alphabet=string.letters[0:52]+string.digits+string.punctuation #defines alphabet to be used
	   word=''
	   wordlist=open("wordlist.txt", "w+") #creates file to hold wordlist
	   for count in xrange(0, wordMax):
	       for x in random.sample(alphabet, random.randint(minimum, maximum)): #takes random characters from alphabet
		    word+=x #adds random character to word
	       wordlist.write(word+'\n') #writes word to word list file
	       word=''
	   wordlist.close() #closes word list file

	print "Generate word list"
	#defines a top level-a new window-for generating word list
	wordInterface=Tkinter.Toplevel(self)
	wordInterface.grid()
	wordInterface.wm_title("Generate Word List")

	#defines a min word length text box
	mintextbox=Tkinter.Text(wordInterface, height=1)
	mintextbox.insert(END, "Enter minimum word length here")
	mintextbox.grid(column=0, row=0)	

	#defines a max word length text box
	maxtextbox=Tkinter.Text(wordInterface, height=1)
	maxtextbox.insert(END, "Enter the maximum word length here")
	maxtextbox.grid(column=0, row=1)

	#defines a word count text box
	counttextbox=Tkinter.Text(wordInterface, height=1)
	counttextbox.insert(END, "Enter number of words here")
	counttextbox.grid(column=0, row=2)

	#defines a generate button
	button=Tkinter.Button(wordInterface, text=u"Generate", command=generate)
	button.grid(column=0, row=3)

#Wireless Cracker Class
class wcGUI(Tkinter.Tk):
	#function that defines initial GUI
   def __init__(self, parent):
	Tkinter.Tk.__init__(self, parent)
	self.parent=parent
	self.initialise()

	#function that initialises GUI
   def initialise(self):
	self.grid() #sets GUI to use grid format

	#defines a scrollable text box
	scrollbar=Tkinter.Scrollbar(self)
	self.textbox=Tkinter.Text(self)
	scrollbar.config(command=self.textbox.yview)
	self.textbox.config(yscrollcommand=scrollbar.set)
	self.textbox.grid(column=0, row=0, rowspan=2)

	#defines a scan button
	scanbutton=Tkinter.Button(self, text=u"Scan", command=self.OnScan)
	scanbutton.grid(column=1, row=0)

	#defines a crack button
	crackbutton=Tkinter.Button(self, text=u"Crack", command=self.OnCrack)
	crackbutton.grid(column=1, row=1)

	#function that performs scanning
   def OnScan(self):
	command=['iwlist', 'wlan0', 'scan'] #specifies command for scanning
	output=subprocess.Popen(command, stdout=subprocess.PIPE).stdout.readlines() #runs scanning command as a subprocess
	data=[]
	wifiFile=open("wifiReport.txt", "w+") #creates file to hold results of scan

	for item in output:
	   wifiFile.write(item) #writes results to wifiReport.txt
	self.textbox.insert(Tkinter.END, "The results of the scan can be found in: wifiReport.txt")
	self.textbox.update_idletasks()

	#function that defines wireless cracking GUI and performs cracking
   def OnCrack(self):
   #function that performs wireless cracking 
	def OnCrackButtonClick():
		ssid=ssidtextbox.get(1.0, Tkinter.END).replace('\n', '')
		apmac=mactextbox.get(1.0, Tkinter.END).replace('\n', '')
		channel=channeltextbox.get(1.0, Tkinter.END).replace('\n', '')
		interface=interfacetextbox.get(1.0, Tkinter.END).replace('\n', '')
		passfile=wordtextbox.get(1.0, Tkinter.END).replace('\n', '')
	
		airodumpcmd=['airodump-ng','-w psk',interface] #specifies command to capture packets for analysis
		airodumpout=subprocess.Popen(airodumpcmd, shell=True) #runs command using subprocess
		time.sleep(10)
		aircrackcmd=['aircrack-ng','-w'+passfile,'-b'+apmac,' psk*.cap'] #specifies command to crack wireless
		aircrackout=subprocess.Popen(aircrackcmd, stdout=subprocess.PIPE).stdout.readlines() #runs command as subprocess
		
		for item in aircrackout:
		   item=item.strip()
		   keyPos=item.find("KEY FOUND:")
		   if keyPos>0: #checks if the key was found
			key=item[keyPos]
		   else:
			key="Key not found."
		#inserts results into text box
		self.textbox.insert(Tkinter.END, ""+ssid+": "+key)
		self.textbox.update_idletasks()
		dialogueInterface.destroy()

		#function that opens file dialogue box, and inserts file path into word file text box
	def OnWordButtonClick():
		global word_file_path
		word_file_path=tkFileDialog.askopenfilename()
		wordtextbox.delete(1.0, Tkinter.END)
		wordtextbox.insert(Tkinter.END, word_file_path)
		wordtextbox.update_idletasks()

		#defines a new top level-a new window-for cracking wireless networks
	dialogueInterface=Tkinter.Toplevel(self)
	dialogueInterface.grid()
	dialogueInterface.wm_title("Crack Wireless Dialogue Box")

	#defines ssid text box
	ssidtextbox=Tkinter.Text(dialogueInterface, height=1)
	ssidtextbox.insert(END, "Please enter the SSID")
	ssidtextbox.grid(column=0, row=0)

	#defines mac address text box
	mactextbox=Tkinter.Text(dialogueInterface, height=1)
	mactextbox.insert(END, "Please enter the MAC address")
	mactextbox.grid(column=0, row=1)

	#defines word list text box
	wordtextbox=Tkinter.Text(dialogueInterface, height=1)
	wordtextbox.insert(END, "Please choose a word list")
	wordtextbox.grid(column=0, row=2)

	#defines word list button
	wfilebutton=Tkinter.Button(dialogueInterface, text=u"Choose File", command=OnWordButtonClick)
	wfilebutton.grid(column=1, row=2)

	#defines channel number text box
	channeltextbox=Tkinter.Text(dialogueInterface, height=1)
	channeltextbox.insert(END, "Please enter the channel number")
	channeltextbox.grid(column=0, row=3)

	#defines wireless interface name text box
	interfacetextbox=Tkinter.Text(dialogueInterface, height=1)
	interfacetextbox.insert(END, "Please enter the wireless interface name")
	interfacetextbox.grid(column=0, row=4)

	#defines crack button
	crackbutton=Tkinter.Button(dialogueInterface, text=u"Crack", command=OnCrackButtonClick)
	crackbutton.grid(column=0, row=5)

#Base System GUI
class Hydra(Tkinter.Tk):
#function that defines initial GUI
   def __init__(self, parent):
	Tkinter.Tk.__init__(self, parent)
	self.parent=parent
	self.initialise()

	#function that initialises GUI
   def initialise(self):
	self.grid() #sets GUI to use grid layout
	
	#defines a wireless cracker button
	wirelessbutton=Tkinter.Button(self, text=u"Wireless Cracker", command=self.OnWireless)
	wirelessbutton.grid(column=0, row=0)

	#defines a network miner button
	networkbutton=Tkinter.Button(self, text=u"Network Miner", command=self.OnNetwork)
	networkbutton.grid(column=2, row=0)

	#defines a password cracker button
	passwordbutton=Tkinter.Button(self, text=u"Password Cracker", command=self.OnPassword)
	passwordbutton.grid(column=1, row=1)

	#defines a forensic tool button
	forensicbutton=Tkinter.Button(self, text=u"Forensic Tool", command=self.OnForensic)
	forensicbutton.grid(column=0, row=2)

	#defines a packet sniffer button
	packetbutton=Tkinter.Button(self, text=u"Packet Sniffer", command=self.OnPacket)
	packetbutton.grid(column=2, row=2)

	#function to run wireless cracker gui
   def OnWireless(self):
	app=wcGUI(None)
   	app.title('Wireless Cracker')
   	app.mainloop()

	#function to run network miner gui
   def OnNetwork(self):
	app=nmGUI(None)
	app.title('Network Miner')
	app.mainloop()

	#function to run password cracker gui
   def OnPassword(self):
	app=pcGUI(None)
   	app.title('Password Cracker')
   	app.mainloop()

	#function to run forensic tool gui
   def OnForensic(self):
	app=ftGUI(None)
	app.title('Forensic Tool')
	app.mainloop()

	#function to run packet sniffer gui
   def OnPacket(self):
	app=psGUI(None)
   	app.title('Packet Sniffer')
   	app.mainloop()

if __name__=="__main__":
#runs base system gui
   app=Hydra(None)
   app.title('Hydra')
   app.mainloop()
