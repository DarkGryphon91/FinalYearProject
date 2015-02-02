import pyPdf, sys, zipfile
import PIL
import xml.dom.minidom as xmlDOM
import xml.etree.ElementTree as ET 
from pyPdf import PdfFileReader
from PIL import Image
from PIL.ExifTags import TAGS

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
while True:
   print "Welcome to the Forensic Tool."
   print "1) Retrieve PDF Metadata."
   print "2) Retrieve Video File Metadata."
   print "3) Retrieve Image File Metadata."
   print "4) Retrieve Audio File Metadata."
   print "5) Retrieve Microsoft Office Documents Metadata."
   print "6) Retrieve Deleted File."
   print "7) Exit the program."
   choice=raw_input("Please enter the function of your choice: ")

   for case in switch(choice):
       if case('1'):
	   print "You chose to retrieve PDF metadata."
	   fileName="GettingStarted.pdf"
	   pdfFile = PdfFileReader(file(fileName, 'rb')) 
	   docInfo = pdfFile.getDocumentInfo() 
	   print '[*] PDF MetaData For: ' + str(fileName)
	   for metaItem in docInfo:  
		print '[+] ' + metaItem + ':' + docInfo[metaItem] 
	   break
       if case('2'):
	   print "You chose to retrieve Video File metadata."
	   videofile=open("Sleepy.Hollow.S02E07.mp4", "rb")
	   tagdata=videofile.read(20000)
	   print str(tagdata)
	   break
       if case('3'):
	   print "You chose to retrieve Image File metadata."
	   imgFileName="DSC_0001.jpg"
	   immetfile=open("imageMetadata.txt", "w+")
	   for (k,v) in Image.open(imgFileName)._getexif().iteritems():
        	#print '%s = %s' % (TAGS.get(k), v)
		immet='%s = %s'%(TAGS.get(k), v)
		immetfile.write(immet+'\n')
	   break
       if case('4'):
	   print "You chose to retrieve Audio File metadata."
	   MP3tagList=["TP1", "TT2", "PRIV", "TCOM", "TCON"]
	   WMAtaglist=["/Year", "/EncodingTIme", "/Composer", "/Publishe", "/Genre",
		       "/AlbumTitle", "/AlbumArtist", "/MCDI", "/TrackNumber"]
	   afile="03 Supermassive Black Hole.wma"
	   audiofile=open(afile, "rb")
	   if "." in afile:
		filetype=afile.split('.')[1]
		for ftype in switch(filetype):
		   if ftype("mp3"):
			print "Decoding mp3 file"
			break
		   if ftype("wma"):
			print "Decoding wma file"
	   		tagdata=audiofile.read(8000)
	   		for tag in WMAtaglist:
			   posmeta=tagdata.find(tag)
			   print ""+tag+": "+str(tagdata[posmeta+8])+"\n"
			break
	   break
       if case('5'):
	   print "You chose to retrieve Microsoft Office Documents metadata."
	   zfile=zipfile.ZipFile('1)Number Theory Notes.pptx')
	   xml=ET.XML(zfile.read('docProps/core.xml'))
	   xml=ET.tostring(xml)
	   xml=xmlDOM.parseString(xml)
	   print xml.toprettyxml()
	   break
       if case('6'):
	   print "You chose to retrieve a deleted file."
	   possible_drives=[r"\\.\PhysicalDrive1", r"\\.\PhysicalDrive2", r"\\.\PhysicalDrive3",
			    "/dev/mmcblk0", "/dev/mmcblk1","/dev/mmcblk2",
	   		    "/dev/sdb","/dev/sdc","/dev/sdd",
			    "/dev/disk1","/dev/disk2","/dev/disk3", 
			    "/dev/sda", "/dev/sda1", "/dev/sda2", "/dev/sda5",]
	   sector_size=512
	   for drive in possible_drives:
		print "In drive: "+drive
		try:
		   disk=file(drive,'rb')
		   print "Disk: "+drive+" read"
		   disk.seek(14000*sector_size)
		   if "Hydra" in disk:
			print "Hydra found at "+drive
			break
		except Exception,e:
		   print "Failed at drive: "+drive
		   print str(e)
		   pass
	   break
       if case('7'):
	   print "You chose to exit."
	   sys.exit()
	   break
       else:
	   print "Invalid Choice."
 



