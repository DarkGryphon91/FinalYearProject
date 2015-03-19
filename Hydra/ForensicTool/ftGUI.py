import Tkinter, tkFileDialog
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

	self.entryVariable=Tkinter.StringVar()
	self.entry=Tkinter.Entry(self, textvariable=self.entryVariable, width=100)
	self.entry.grid(column=0, row=0, sticky='EW')
	self.entryVariable.set(u"Please choose a file")

	filebutton=Tkinter.Button(self, text=u"Choose File", command=self.OnButtonClick)
	filebutton.grid(column=1, row=0)

	self.labelVariable=Tkinter.StringVar()
	label=Tkinter.Label(self, textvariable=self.labelVariable, height=15, anchor="w", fg="black", bg="white", wraplength=450)
	label.grid(column=0, row=1, columnspan=2, sticky='EW')
	self.labelVariable.set(u"Metadate is displayed here.")

	extractbutton=Tkinter.Button(self, text=u"Extract", command=self.extract)
	extractbutton.grid(column=2, row=2)

   def OnButtonClick(self):
	global file_path
	file_path=tkFileDialog.askopenfilename()
	self.entryVariable.set(file_path)

   def extract(self):
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
	      self.labelVariable.set(pdfMeta)
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
	      self.labelVariable.set(vidMeta)
	      break
            if case('jpg') or case('JPG'):
	      print "You chose to retrieve Image File metadata."
	      imgFileName=file_path
	      immetfile=open("imageMetadata.txt", "w+")
	      for (k,v) in Image.open(imgFileName)._getexif().iteritems():
		  immet='%s = %s'%(TAGS.get(k), v)
		  immetfile.write(immet+'\n')
	      self.labelVariable.set("The metadata for this file can be found in: imageMetadata.txt")
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
	      self.labelVariable.set("The metadata for this file can be found in: audioMetadata.txt")
	      break
            if case('docx') or case('pptx') or case('xlsx'):
	      print "You chose to retrieve Microsoft Office Documents metadata."
	      docfile=file_path
	      zfile=zipfile.ZipFile(docfile)
	      xml=ET.XML(zfile.read('docProps/core.xml'))
	      xml=ET.tostring(xml)
	      xml=xmlDOM.parseString(xml)
	      docMeta=xml.toprettyxml()
	      self.labelVariable.set(docMeta)
	      break

if __name__=="__main__":
   app=ftgui(None)
   app.title('Forensic Tool')
   app.mainloop()
