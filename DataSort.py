import pprint

def sort():
	f = open("./res")
	f1 = open("./result",'w') 
	lines = f.readlines()
#	pprint.pprint(lines)
	last_tag = 0
	now_tag = 0
	WBlines = []
	for linenum in range(len(lines)):
		if lines[linenum] == ";0\n" or lines[linenum] == ";1\n":
			last_tag = now_tag
			now_tag = linenum
#			print last_tag,now_tag			
			for line in (lines[(last_tag+1):now_tag]):
				print line
				if line.strip().split()[3] == "RRSIG":
					pass
				elif line.strip().split()[3] == "A":
#					print "*****"+line[:-1]+'\t'+lines[now_tag][1:]
					WBlines.append(line[:-1]+'\t\t\t\t\t\t'+lines[now_tag][1:])
				elif line.strip().split()[3] == "AAAA":
#					print "*****"+line[:-1]+'\t'+lines[now_tag][1:]	
					WBlines.append(line[:-1]+'\t\t\t\t\t\t'+lines[now_tag][1:])
				elif line.strip().split()[3] == "NS":
#					print "*****"+line[:-1]+lines[now_tag]+'\n'	
					WBlines.append(line[:-1]+'\t\t\t\t\t\t'+lines[now_tag][1:])

	f1.writelines(WBlines)
	f.close()
	f1.close()		
			
			
if __name__ == "__main__":
	sort()
