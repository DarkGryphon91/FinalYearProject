The following are the libraries needed in Python to run Hydra.
1.pygeoip
2.pypdf
3.dpkt
4.hachoir-metadata
5.hachoir-core(optional-may be installed with hachoir-metadata)
6.hachoir-parser(optional-may be installed with hachoir-metadata)
7.aircrack-ng
The following are instructions on how to run Hydra.
 1.Packet Sniffer-this program should be run with sudo privileges. It will output four files contained in a date stamped folder. 
	These four files are:
						 1.packets-this contains the full transcript of the packets captured for the user to view and analyse themselves
						 2.downloaded-this contains a list of IP addresses that have downloaded a particular program-LOIC(a denial of service attack program). 
									  This may be changed to add new programs in the future.
						 3.ipLocations-this contains the source and destination city and country of every IP packet that has been found.
						 4.attackList-this contains a list of IP addresses that have launched a denial of service attack using LOIC. 
 2.Network Miner-this program should also run with sudo privileges. It will output the IP address of every computer active on the network, make an educated guess
				 at the operating system that it uses, and scan the computers for open ports. At the start the user may specify a quick scan-1024 ports, or
				 a full scan-65000 ports.
 3.Password Cracker-this program doesn't need sudo privileges to run, however for cracking user passwords, the user needs to have copied either the 
					Linux /etc/shadow file, or the Windows SAM file either of which may need sudo privileges. This program comes with a password list, which
					contains 10,000 of the most common passwords. There are four choices for the user to make on 
					starting:
							 1.User password-for this option the user specifies the password file copy they have made, the wordlist they would like to user
											 and the operating system that the machine is-this is to allow the program to differentiate between Linux and Windows.
							 2.Zip file password-for this option the user specifies the zip file they want cracked. The program will then attempt to crack that password
												 using the specified list.
							 3.Website password-for this option the user specifies the login url for the website, username and password list. The program will
												then attempt to crack the password for that user.
							 4.Wordlist generator-for this option the user specifies the minimum/maximum length, maximum amount of words to be generated.
												  The program will then create random words made up of random numbers/letters/punctuation marks that fit the specified
												  criteria.
 4.Forensic Tool-this program doesn't need sudo privileges to run. There are six choice for the user to make on starting.
	These six choices are:
						  1.PDF-the user specifies the pdf file. The program will then extract the metadata for this file, and print to the screen.
						  2.Video-the user specifies the video file. The program will then extract the metadata for this file, and print to the screen. 
						  3.Image-the user specifies the image file. The program will then extract the metadata for this file, 
						          and print to a file called "imageMetadata.txt"
						  4.Audio-the user specifies the audio file. The program will then extract the metadata for this file, and print to the screen.
						  5.Microsoft Office Document-the user specifies the audio file. The program will then extract the metadata for this file, 
													  and print to the screen. This metadata will be in XML format.
						  6.Deleted File-this functionality isn't currently working however in a later version this will be fixed.
 5.Wireless Cracker-this program needs sudo privileges, and aircrack installed to run. It will scan the wireless networks and produce a report on all available. 
					The details in this report are then used by the user to crack the wireless network using aircrack-this functionality isn't currently working
					however in a later version this will be fixed. Before running the program please place the wireless interface into monitor mode.
 