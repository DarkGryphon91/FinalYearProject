audiofile=open("test.txt", "r+")
rdata=audiofile.read()
mp3TagList={"AENC":"Audio Encryption", "APIC":"Attached Picture", "COMM":"Comments", "COMR":"Commercial Frame", "ENCR":"Encryption method registration", "EQUA":"Equalisation", "ETCO":"Event timing codes", "GEOB":"General Encapsulated Object", "GRID":"Group Identification Registration", "IPLS":"Involoved People list", "LINK":"Linked Information", "MCDI":"Music CD Identifier", "MLLT":"MPEG Location Lookup Table", "OWNE":"Ownership Frame", "PRIV":"Private Frame", "PCNT":"Play COunter", "POPM":"Popularimeter", "POSS":"Position Synchronisation Frame", "RBUF":"Recommended Buffer Size", "RVAD":"Relative Volume Adjustment", "RVRB":"Reverb", "SYLT":"Synchronised Lyric/Text", "SYTC":"Synchronised Tempo Codes", "TALB":"Album", "TBPM":"Beats Per Minute", "TCOM":"Composer", "TCON":"Content Type", "TCOP":"Copyright Message", "TDAT":"Date", "TDLY":"Playlist Delay", "TENC":"Encoded By", "TEXT":"Lyricist/Text Writer", "TFLT":"File Type", "TIME":"Time", "TIT1":"Content Group Description", "TIT2":"Title", "TIT3":"Subtitle", "TKEY":"Initial Key", "TLAN":"Language", "TLEN":"Length", "TMED":"Media Type", "TOAL":"Original Album", "TOFN":"Original Filename", "TOLY":"Original Lyricist/Text Writer", "TOPE":"Original Artist", "TORY":"Original Release Year", "TOWN":"File Owner", "TPE1":"Lead Performer", "TPE2":"Band Accompaniment", "TPE3":"Conductor", "TPE4":"Interpreted By", "TPOS":"Part of a Set", "TPUB":"Publisher", "TRCK":"Track Number", "TRDA":"Recording Dates", "TRSN":"Internet Radio Station Name", "TRSO":"Internet Radio Station Owner", "TSIZ":"Size", "TSRC":"International Standard Recording Code", "TSSE":"Software/Hardware and settings used for encoding", "TYER":"Year", "TXXX":"User defined test information frame", "UFID":"Unique File Indentifier", "USER":"Terms of Use", "USLT":"Unsynchronised Lyric Transcription", "WCOM":"Commercial Information", "WCOP":"Copyright Information", "WOAF":"Official audio file webpage", "WOAR":"Official artist/performer webpage", "WOAS":"Official audio source webpage", "WORS":"Official internet radio station homepage", "WPAY":"Payment", "WPUB":"Publishers official webpage", "WXXX":"User defined URL link frame"}
byteList=["\\x00","\\x01","\\x02","\\x03","\\x04","\\x05","\\x06","\\x07",
	  "\\x08","\\x09","\\x0a","\\x0b","\\x0c","\\x0d","\\x0e","\\x0f"]
print rdata
for byte in byteList:
   rdata=rdata.replace(byte, '')
print rdata
for tag,meaning in mp3TagList.iteritems():
   tagPos=rdata.find(tag)
   if tagPos>0:
	rdata=rdata[:tagPos]+'\n'+rdata[tagPos:]
	rdata=rdata.replace(tag, meaning)
	
print rdata

