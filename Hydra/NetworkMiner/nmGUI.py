import Tkinter
import socket, sys
from struct import *
from Tkinter import *

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

	
if __name__=="__main__":
   app=nmGUI(None)
   app.title('Network Miner')
   app.mainloop()
