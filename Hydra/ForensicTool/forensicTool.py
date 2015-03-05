import pyPdf, sys, zipfile, struct
import PIL
import xml.dom.minidom as xmlDOM
import xml.etree.ElementTree as ET 
from pyPdf import PdfFileReader
from PIL import Image
from PIL.ExifTags import TAGS
from hachoir_metadata import metadata
from hachoir_core.cmd.line import unicodeFilename
from hachoir parser import createParser

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
	   fileName=raw_input("Please enter the name of the pdf document: ")
	   pdfFile = PdfFileReader(file(fileName, 'rb')) 
	   docInfo = pdfFile.getDocumentInfo() 
	   print '[*] PDF MetaData For: ' + str(fileName)
	   for metaItem in docInfo:  
		print '[+] ' + metaItem + ':' + docInfo[metaItem] 
	   break
       if case('2'):
	   print "You chose to retrieve Video File metadata."
	   filename = raw_input("Please enter the name of the video file: ")
	   filename, realname = unicodeFilename(filename), filename
	   parser = createParser(filename)

	   for k,v in metadata.extractMetadata(parser)._Metadata__data.iteritems():
	      if v.values:
                 print v.key, v.values[0].value
	   break
       if case('3'):
	   print "You chose to retrieve Image File metadata."
	   imgFileName=raw_input("Please enter the name of the image: ")
	   immetfile=open("imageMetadata.txt", "w+")
	   for (k,v) in Image.open(imgFileName)._getexif().iteritems():
		immet='%s = %s'%(TAGS.get(k), v)
		immetfile.write(immet+'\n')
	   print "The metadata for this file can be found in: imageMetadata.txt"
	   break
       if case('4'):
	   print "You chose to retrieve Audio File metadata."
	   afile=raw_input("Please enter the name of the mp3 file: ")
	   audiofile=open(afile, "rb")
	   mdfile=open("audioMetadata.txt", "w+")
	   print "Decoding mp3 file"
	   md=audiofile.read(1500)
	   print repr(md)
	   metad=repr(md)
	   mdfile.write(metad)
	   mp3TagList={"AENC":"Audio Encryption", "APIC":"Attached Picture", "COMM":"Comments", "COMR":"Commercial Frame", "ENCR":"Encryption method registration", "EQUA":"Equalisation", "ETCO":"Event timing codes", "GEOB":"General Encapsulated Object", "GRID":"Group Identification Registration", "IPLS":"Involoved People list", "LINK":"Linked Information", "MCDI":"Music CD Identifier", "MLLT":"MPEG Location Lookup Table", "OWNE":"Ownership Frame", "PRIV":"Private Frame", "PCNT":"Play COunter", "POPM":"Popularimeter", "POSS":"Position Synchronisation Frame", "RBUF":"Recommended Buffer Size", "RVAD":"Relative Volume Adjustment", "RVRB":"Reverb", "SYLT":"Synchronised Lyric/Text", "SYTC":"Synchronised Tempo Codes", "TALB":"Album", "TBPM":"Beats Per Minute", "TCOM":"Composer", "TCON":"Content Type", "TCOP":"Copyright Message", "TDAT":"Date", "TDLY":"Playlist Delay", "TENC":"Encoded By", "TEXT":"Lyricist/Text Writer", "TFLT":"File Type", "TIME":"Time", "TIT1":"Content Group Description", "TIT2":"Title", "TIT3":"Subtitle", "TKEY":"Initial Key", "TLAN":"Language", "TLEN":"Length", "TMED":"Media Type", "TOAL":"Original Album", "TOFN":"Original Filename", "TOLY":"Original Lyricist/Text Writer", "TOPE":"Original Artist", "TORY":"Original Release Year", "TOWN":"File Owner", "TPE1":"Lead Performer", "TPE2":"Band Accompaniment", "TPE3":"Conductor", "TPE4":"Interpreted By", "TPOS":"Part of a Set", "TPUB":"Publisher", "TRCK":"Track Number", "TRDA":"Recording Dates", "TRSN":"Internet Radio Station Name", "TRSO":"Internet Radio Station Owner", "TSIZ":"Size", "TSRC":"International Standard Recording Code", "TSSE":"Software/Hardware and settings used for encoding", "TYER":"Year", "TXXX":"User defined test information frame", "UFID":"Unique File Indentifier", "USER":"Terms of Use", "USLT":"Unsynchronised Lyric Transcription", "WCOM":"Commercial Information", "WCOP":"Copyright Information", "WOAF":"Official audio file webpage", "WOAR":"Official artist/performer webpage", "WOAS":"Official audio source webpage", "WORS":"Official internet radio station homepage", "WPAY":"Payment", "WPUB":"Publishers official webpage", "WXXX":"User defined URL link frame"}
	   byteList=["\\x00","\\x01","\\x02","\\x03","\\x04","\\x05","\\x06","\\x07",
	  	     "\\x08","\\x09","\\x0a","\\x0b","\\x0c","\\x0d","\\x0e","\\x0f"]
	   print metad
	   for byte in byteList:
   		metad=metad.replace(byte, '')
		print metad
	   for tag,meaning in mp3TagList.iteritems():
   		tagPos=metad.find(tag)
   		if tagPos>0:
		   metad=metad[:tagPos]+'\n'+metad[tagPos:]
		   metad=metad.replace(tag, meaning)
	   print metad	
	   break
       if case('5'):
	   print "You chose to retrieve Microsoft Office Documents metadata."
	   docfile=raw_input("Please enter the name of the Microsoft Office document: ")
	   zfile=zipfile.ZipFile(docfile)
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
 



