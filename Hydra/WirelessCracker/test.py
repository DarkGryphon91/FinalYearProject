import subprocess
from wifi import Cell, Scheme
#from collections import defaultdict
cell = Cell.all('wlan0')[0]
scheme = Scheme.for_cell('wlan0', 'home', cell)
#scheme.save()
scheme.activate()
#command=['iwlist', 'wlan0', 'scan']
#output=subprocess.Popen(command, stdout=subprocess.PIPE).stdout.readlines()
#data=[]
#wifiFile=open("wifiReport.txt", "w+")
#keys=["Quality", "Encryption", "SSID"]
#networks=defaultdict(list)
#networkList=[]
#for item in output:
#   print item.strip()
#   wifiFile.write(item.strip())
#   if item.strip().startswith('ESSID:'):
#	data.append('SSID: '+item.lstrip(' ESSID:"').rstrip('"\n'))
#   if item.strip().startswith('Quality'):
#	data.append('Quality: '+item.split()[0].lstrip(' Quality=').rstrip('/70 '))
 #  if item.strip().startswith('Encryption key:off'):
#	data.append('Encryption: Open')
 #  if item.strip().startswith('Encryption key:on'):
#	data.append('Encryption: Encrypted')
#print data
#print keys
#for value in data:
#   for key in keys:
#	networks[key].append(value)
#networkList.append(dict(zip(keys, data)))
#print networkList
#print networks
