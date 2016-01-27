#!/usr/bin/python

from __future__ import print_function
import re
import subprocess

#ControlPREFIX = "/opt/RootZoneCollector/"
DataPREFIX = "/opt/RootSpider/DataBak"
ControlPREFIX = "/opt/RootSpider"
def ReturnConfig(DataPREFIX,ControlPREFIX):


	#print files
	sub0 = subprocess.Popen("ls -lt -d %s/*.result" % DataPREFIX, stdout=subprocess.PIPE, shell=True)
	sub0.wait()
	reslines = sub0.stdout.readlines()
	if len(reslines) > 0 and len(reslines) < 2:
		print (reslines[0].split()[-1].split('/')[-1]+',',end="")
		output_dnssec_info("%s/%s" % (DataPREFIX,reslines[0].split()[-1].split('/')[-1]))
	elif len(reslines) > 0 and len(reslines) < 3:
		print (reslines[0].split()[-1].split('/')[-1]+',',end="")
		output_dnssec_info("%s/%s" % (DataPREFIX,reslines[0].split()[-1].split('/')[-1]))		
		print (reslines[1].split()[-1].split('/')[-1]+',',end="")
		output_dnssec_info("%s/%s" % (DataPREFIX,reslines[1].split()[-1].split('/')[-1]))
	elif len(reslines) > 2:
		print (reslines[0].split()[-1].split('/')[-1]+',',end="")
		output_dnssec_info("%s/%s" % (DataPREFIX,reslines[0].split()[-1].split('/')[-1]))		
		print (reslines[1].split()[-1].split('/')[-1]+',',end="")
		output_dnssec_info("%s/%s" % (DataPREFIX,reslines[1].split()[-1].split('/')[-1]))
		print (reslines[2].split()[-1].split('/')[-1]+',',end="")
		output_dnssec_info("%s/%s" % (DataPREFIX,reslines[2].split()[-1].split('/')[-1]))
	else:
		pass
	sub1 = subprocess.Popen("ls -lt -d %s/*.result | wc -l" % DataPREFIX, stdout=subprocess.PIPE, shell=True)
	print (sub1.stdout.readlines()[0].strip()+',',end="\n")

	#print pid
	cmd = 'ps -ef | grep "Root-Spider"'
	sub = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
	sub.wait()
	reslines = sub.stdout.readlines()
	judgeifrun = 0
	for lines in reslines:
		if lines.split()[2] == '1':
			print ("pid=%s," % lines.split()[1])
			judgeifrun = 1
			break
	if judgeifrun == 0:
		print ("pid=0,")

	#print logfile
	print ("logpath=%s/%s" % (ControlPREFIX,"runlog"))
	



def output_dnssec_info(filename):
	f = open(filename)
	dnssecnum = 0
	totalnum = 0
	lines = f.readlines()
	totalnum = len(lines)
	for line in lines:
		if line.strip().split()[-1] == "1":
			dnssecnum  = dnssecnum+1
	print ("dnssecnum=%s,totalnum=%s" % (str(dnssecnum),str(totalnum)))	


if __name__ == "__main__":
	ReturnConfig(DataPREFIX,ControlPREFIX)
