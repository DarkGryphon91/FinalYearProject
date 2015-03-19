import Tkinter, tkFileDialog
import crypt, sys, string, random, re, urllib, urllib2, zipfile, hashlib

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
		userentryVariable.set(user_file_path)

	def OnWordButtonClick():
		global word_file_path
		word_file_path=tkFileDialog.askopenfilename()
		wordentryVariable.set(word_file_path)

	def OnCrack():
		pfile=user_file_path
	   	dfile=word_file_path
	   	osystem=osentryVariable.get()
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
		labelVariable.set(result)
	print "Crack User"
	userInterface=Tkinter.Toplevel(self)
	userInterface.grid()
	userInterface.wm_title("Crack User Password")

	userentryVariable=Tkinter.StringVar()
	userentry=Tkinter.Entry(userInterface, textvariable=userentryVariable, width=50)
	userentry.grid(column=0, row=0, sticky='EW')
	userentryVariable.set(u"Please choose a file containing encrypted user details")

	ufilebutton=Tkinter.Button(userInterface, text=u"Choose File", command=OnUserButtonClick)
	ufilebutton.grid(column=1, row=0)

	wordentryVariable=Tkinter.StringVar()
	wordentry=Tkinter.Entry(userInterface, textvariable=wordentryVariable, width=50)
	wordentry.grid(column=0, row=1, sticky='EW')
	wordentryVariable.set(u"Please choose a word list")

	wfilebutton=Tkinter.Button(userInterface, text=u"Choose File", command=OnWordButtonClick)
	wfilebutton.grid(column=1, row=1)

	osentryVariable=Tkinter.StringVar()
	osentry=Tkinter.Entry(userInterface, textvariable=osentryVariable, width=50)
	osentry.grid(column=0, row=2, sticky='EW')
	osentryVariable.set(u"Please enter user's operating system")

	labelVariable=Tkinter.StringVar()
	label=Tkinter.Label(userInterface, textvariable=labelVariable, height=20, anchor="w", fg="black", bg="white")
	label.grid(column=0, row=3, columnspan=2, sticky='EW')
	labelVariable.set(u"Cracked Password goes here.")

	crackButton=Tkinter.Button(userInterface, text=u"Crack", command=OnCrack)
	crackButton.grid(column=0, row=4)

   def crackZip(self):
	def OnZipButtonClick():
		global zip_file_path
		zip_file_path=tkFileDialog.askopenfilename()
		fileentryVariable.set(zip_file_path)

	def OnWordButtonClick():
		global word_file_path
		word_file_path=tkFileDialog.askopenfilename()
		wordentryVariable.set(word_file_path)

	def onCrack():
		specfile=zip_file_path
   		specpassfile=word_file_path
   		zFile=zipfile.ZipFile(specfile)
   		passFile=open(specpassfile, "r")
   		for line in passFile.readlines():
      		    password=line.strip('\n')
      		    try:
	   		zFile.extractall(pwd=password)
			labelVariable.set("Password: "+password)
      		    except Exception, e:
	   		pass
	print "Crack Zip file"
	zipInterface=Tkinter.Toplevel(self)
	zipInterface.grid()
	zipInterface.wm_title("Crack Zip File Password")

	fileentryVariable=Tkinter.StringVar()
	fileentry=Tkinter.Entry(zipInterface, textvariable=fileentryVariable, width=50)
	fileentry.grid(column=0, row=0, sticky='EW')
	fileentryVariable.set(u"Please choose a zip file")

	zfilebutton=Tkinter.Button(zipInterface, text=u"Choose File", command=OnZipButtonClick)
	zfilebutton.grid(column=1, row=0)

	wordentryVariable=Tkinter.StringVar()
	wordentry=Tkinter.Entry(zipInterface, textvariable=wordentryVariable, width=50)
	wordentry.grid(column=0, row=1, sticky='EW')
	wordentryVariable.set(u"Please choose a word list")

	wfilebutton=Tkinter.Button(zipInterface, text=u"Choose File", command=OnWordButtonClick)
	wfilebutton.grid(column=1, row=1)

	labelVariable=Tkinter.StringVar()
	label=Tkinter.Label(zipInterface, textvariable=labelVariable, anchor="w", fg="black", bg="white")
	label.grid(column=0, row=2, columnspan=2, sticky='EW')
	labelVariable.set(u"Cracked Password goes here.")

	crackButton=Tkinter.Button(zipInterface, text=u"Crack", command=onCrack)
	crackButton.grid(column=0, row=3)
	

   def crackWebsite(self):
	def OnWordButtonClick():
		global word_file_path
		word_file_path=tkFileDialog.askopenfilename()
		wordentryVariable.set(word_file_path)
	
	def OnCrack():
		host=webentryVariable.get()
	   	usr=userentryVariable.get()
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
		  	labelVariable.set("Successful Login: ",usr, word)

	print "Crack website"
	webInterface=Tkinter.Toplevel(self)
	webInterface.grid()
	webInterface.wm_title("Crack Website Password")

	wordentryVariable=Tkinter.StringVar()
	wordentry=Tkinter.Entry(webInterface, textvariable=wordentryVariable, width=50)
	wordentry.grid(column=0, row=1, sticky='EW')
	wordentryVariable.set(u"Please choose a word list")

	wfilebutton=Tkinter.Button(webInterface, text=u"Choose File", command=OnWordButtonClick)
	wfilebutton.grid(column=1, row=1)

	webentryVariable=Tkinter.StringVar()
	webentry=Tkinter.Entry(webInterface, textvariable=webentryVariable, width=50)
	webentry.grid(column=0, row=2, sticky='EW')
	webentryVariable.set(u"Please enter login url of website")

	userentryVariable=Tkinter.StringVar()
	userentry=Tkinter.Entry(webInterface, textvariable=userentryVariable, width=50)
	userentry.grid(column=0, row=3, sticky='EW')
	userentryVariable.set(u"Please enter the username")

	errorvar = Tkinter.StringVar()
	# initial value
	errorvar.set('Please choose the login error')
	choices = ['error_invalid_auth']
	option = Tkinter.OptionMenu(webInterface, errorvar, *choices)
	option.grid(column=0, row=4)

	labelVariable=Tkinter.StringVar()
	label=Tkinter.Label(webInterface, textvariable=labelVariable, anchor="w", fg="black", bg="white")
	label.grid(column=0, row=5, columnspan=2, sticky='EW')
	labelVariable.set(u"Cracked Password goes here.")

	crackButton=Tkinter.Button(webInterface, text=u"Crack", command=OnCrack)
	crackButton.grid(column=0, row=6)

   def generateWordList(self):
	def generate():
	   minimum=int(minentryVariable.get())
	   maximum=int(maxentryVariable.get())
	   wordMax=int(countentryVariable.get())
	
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

	minentryVariable=Tkinter.StringVar()
	minentry=Tkinter.Entry(wordInterface, textvariable=minentryVariable, width=30)
	minentry.grid(column=0, row=0, sticky='EW')
	minentryVariable.set(u"Enter minimum word length here")

	maxentryVariable=Tkinter.StringVar()
	maxentry=Tkinter.Entry(wordInterface, textvariable=maxentryVariable, width=30)
	maxentry.grid(column=0, row=1, sticky='EW')
	maxentryVariable.set(u"Enter maximum word length here")

	countentryVariable=Tkinter.StringVar()
	countentry=Tkinter.Entry(wordInterface, textvariable=countentryVariable, width=30)
	countentry.grid(column=0, row=2, sticky='EW')
	countentryVariable.set(u"Enter number of words here")

	button=Tkinter.Button(wordInterface, text=u"Generate", command=generate)
	button.grid(column=0, row=3)

if __name__=="__main__":
   app=pcGUI(None)
   app.title('Password Cracker')
   app.mainloop()
