from __future__ import print_function
import getopt
import sys
import re
import getopt
import subprocess
import time

ControlPREFIX = "/opt/RootSpider"

def startService(ControlPREFIX):
	cmd = 'ps -ef | grep "Root-Spider"'
	sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
	sub.wait()
	reslines = sub.stdout.readlines()
	for lines in reslines:
		if lines.split()[2] == '1':
			print("program already start")
			return	

	cmd1 = "python %s/Root-Spider.py > %s/runlog &" % (ControlPREFIX,ControlPREFIX)
	sub1 = subprocess.Popen(cmd1, stdout=subprocess.PIPE, shell=True)
	sub1.wait()

	sub2 = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
	reslines = sub2.stdout.readlines()
	pid = "dummy"
	for lines in reslines:
		if lines.split()[2] == '1':
			pid = lines.split()[1]
			print (pid)
		
	
def stopService(ControlPREFIX):
	cmd = 'ps -ef | grep "Root-Spider"'
	sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
	sub.wait()
	reslines = sub.stdout.readlines()
	pid = "dummy"
	for lines in reslines:
		if lines.split()[2] == '1':
			pid = lines.split()[1]
			print (pid)
 
	sub1 = subprocess.Popen("sudo kill -9 %s" % pid, stdout=subprocess.PIPE, shell=True)
	sub1.wait()



'''
def updateConfiguration(ControlPREFIX,value):
	items = value.strip().split(',')
#	print (items)
	f = open(ControlPREFIX+"Configuration.in",'r')
#	print (ControlPREFIX+"Configuration.in")
	filelines = f.readlines()
#	print (filelines)
	for i in range(len((filelines))):
		if filelines[i].strip().split()[0] == "period":
				filelines[i] = "%s\t%s\t%s\n" % ("period","=",items[2])
		if filelines[i].strip().split()[0] == "ZoneDir":
				filelines[i] = "%s\t%s\t%s\n" % ("ZoneDir","=",items[0][7:])
		if filelines[i].strip().split()[0] == "SigDir":
				filelines[i] = "%s\t%s\t%s\n" % ("SigDir","=",items[1][7:])		
	f.close()
#	print (filelines)
	f = open(ControlPREFIX+"Configuration.in",'w')
	f.writelines(filelines)
	f.close()

	stopService(ControlPREFIX)
	startService(ControlPREFIX)
'''



def runServiceOnce(ControlPREFIX):
	cmd = "python %s/Root-Spider-Basic.py > %s/runlog &" % (ControlPREFIX,ControlPREFIX)
	sub = subprocess.Popen(cmd, shell=True)
#	print ("bbb")
#	print (sub.stdout.read())
	sub.wait()
	print ("running...")
#	time.sleep(20)
#	print ("aaa")
#	print (sub.stdout.read())

def main(argv):
	try:
		opts,args = getopt.getopt(argv[1:], "h", ["stop","start","restart","runonce","update="])
	except getopt.GetoptError,info:
		print (info.msg)
		PrintUsage()
		sys.exit()
	for option,value in opts:
		if option in ("--start"):
			startService(ControlPREFIX)
		elif option in ('--stop'):
			stopService(ControlPREFIX)
		elif option in ('--restart'):
			stopService(ControlPREFIX)
			startService(ControlPREFIX)
		elif option in ('--runonce'):
			runServiceOnce(ControlPREFIX)
		elif option in ('--update'):
			updateConfiguration(ControlPREFIX,value)
		elif option in ('-h'):
			PrintUsage()
		else:
			PrintUsage()
			sys.exit()

if __name__ == "__main__":
	main(sys.argv)	
