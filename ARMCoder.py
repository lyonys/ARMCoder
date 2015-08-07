#Author: Lyon Yang
#Date: 7 July 15
#Things to do:
#1. Test if working
#2. Remove join and write encoder

import random
import subprocess
import sys
from subprocess import Popen
import argparse

#Argument Parser
parser = argparse.ArgumentParser(description='SHELLKITARM v0.1')
parser.add_argument('-le','--littleendian', help='Output Little Endian', action='store_true')
parser.add_argument('-be','--bigendian', help='Output Big Endian', action='store_true')
parser.add_argument('-e','--encode',help='Turn on Encoder', action='store_true')
parser.add_argument('-scb','--shellcodebinary',help='Input Shellcode Binary here',required=True)
parser.add_argument('-od','--objdump',help='Objdump binary to use',required=False)
parser.add_argument('-o','--output',help='Output Format. Currently only support python. Example: -o python',required=False)
parser.add_argument('-bc','--badchar',help='Bad Characters. Example: -b \x00\x0a\x20 COMING SOON. STILL WORK IN PROGRESS',required=False)
parser.add_argument('-spos','--startposition',help='Location to encode',required=False,type=int)
parser.add_argument('-epos','--endposition',help='Location to encode',required=False,type=int)

args = vars(parser.parse_args())

#Setup Environment Variables

startencodepos = args['startposition']
endencodepos = args['endposition']	
LE_decoder=("\"\\xf6\\x49\\x14\\x99"
"\\xf6\\xc9\\x14\\x99"
"\\x21\\x")
if startencodepos:
	diff  = endencodepos-startencodepos
	diff = format(((diff * 2) + 36-8),'x')
	LE_decoder += str(diff)
	LE_decoder += "\\x23\\x"
	LE_decoder += str(format((startencodepos+6),'x'))
	
else:
	#Register R1 determine number of loops
	LE_decoder += "21\\xe0"
	#Register R3, Offset for PC
	LE_decoder += "\\x23\\x0e"

LE_decoder+=("\\x46\\x7d\\x58\\xee"
"\\x40\\x66\\x50\\xee"
"\\x46\\xc0\\x33\\x04"
"\\x39\\x08\\x29\\x24"
"\\xda\\xf7\"")
BE_mthumbmode=("\"\\x01\\x10\\x8f\\xe2\\x11\\xff\\x2f\\xe1\"")
BE_decoder=("\"\\x49\\xf6\\x99\\x14"
"\\xc9\\xf6\\x99\\x14")

if startencodepos:
        diff  = endencodepos-startencodepos
	# -8 for extra code to switch to mthumb... Should probably change this to allow customization! as offset is wrong if oyu dont remove the mthumb code
        diff = format(((diff * 2) + 36 -8),'x')
	BE_decoder += "\\x"
        BE_decoder += str(diff)
	BE_decoder += "\\x21\\x"
        BE_decoder += str(format((startencodepos+6),'x'))
        BE_decoder += "\\x23"

else:
        #Register R1 determine number of loops
        BE_decoder += "\\x4c\\x21"
        #Register R3, Offset for PC
        BE_decoder += "\\x5a\\x23"



BE_decoder+=("\\x7d\\x46\\xee\\x58"
"\\x66\\x40\\xee\\x50"
"\\xc0\\x46\\x04\\x33"
"\\x08\\x39\\x24\\x29"
"\\xf7\\xda\"")

#Setup Environment Variables
encode = args['encode']
binary_file = args['shellcodebinary']
num_of_line = 0
payload = ""
num_of_payload = 0
objdumparg = ""
shellcodedump = ""
out_format = 'python'
if args['output']:
	out_format = args['output']

if args['littleendian']:
	objdumparg = '-dEL'
elif args['bigendian']:
	objdumparg = '-dEB'
else:
	objdumparg = '-d'

objdump = 'objdump'
if args['objdump']:
	objdump = args['objdump'] 

proc = subprocess.Popen(['objdump',objdumparg,binary_file], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

while True:
		line = proc.stdout.readline()
		if line != '':
			array2_2 = ""
			array = line.rstrip().split(':')
			if len(array) > 1:
					if array[1]:
						array2 =  array[1].split(' ')
						array2_2 = array2[1].lstrip().rstrip()
						array2 = array2[0].lstrip().rstrip()
					if array2:
						shellcodedump +=array2
						array2=""
						try:
							
							int(array2_2, 16)
							shellcodedump+=array2_2
						except ValueError:
							array2_2=""
		else:
				break

#Setup Encoder Environment variables part 1
encoder_default_value="99999999"

badcharcheck = False
if args['badchar']:
	badchars = args['badchar'].split('\\x')
	badcharcheck = True
	print ">>Check for Bad Characters is on"

badchardetected = True
alpha = ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", 
             "A", "B", "C", "D", "E", "F")

while badchardetected is True:
	badchardetected = False
	#Setup Encoder Environment variables part 2

	index_a = 0
	index_b = 8
	num_of_loops = len(shellcodedump)/8
	num_of_extrabits = len(shellcodedump)%8
	shellcodedump += '0' * num_of_extrabits


	print "================= Shellcode ================="

	#Print Decoder Code if encoder is turned on
	if (encode == True or args['startposition']):
		print "---------------------------------------------"
		print "Mthumb code:"
		print "---------------------------------------------"
		if args['bigendian']:
			print BE_mthumbmode
		print "---------------------------------------------"
		print "Trying to encode with: " + encoder_default_value
		print "Decoder code:"
		print "---------------------------------------------"
		if args['littleendian']:
	        	print LE_decoder
		elif args['bigendian']:
	        	print BE_decoder	
		print "---------------------------------------------"

	#loop through and dump shellcode
	for x in range(0,num_of_loops+1):
		value_to_encode=shellcodedump[index_a:index_b]
		if ((index_a/2 >= (startencodepos) and index_b/2 <= (endencodepos)) or encode == True):
			if value_to_encode:
				encoded_value = '%x' % (int(encoder_default_value,16)^int(value_to_encode,16))
				if len(encoded_value) != 8:
					encoded_value = '0' * (8-len(encoded_value)) + encoded_value
		else:
			encoded_value = value_to_encode
		if out_format == 'python':
			#Append \x
			sc = '"'
			sc += '\\x'
		    	sc += '\\x'.join(a+b for a,b in zip(encoded_value[::2], encoded_value[1::2]))
			sc += '"'

			#Check for bad characters
			valuestocheck = sc.split('\\x')
			if badcharcheck is True:
				for  badchar in badchars:
					if badchar:
						for value in valuestocheck:
							if badchar == value:
								badchardetected = True
								break
					if badchardetected is True:
						break
				print sc
			else:
				if sc != '"\\x"':
					print sc
		index_a += 8
		index_b += 8
		if badchardetected is True:
			break
	if badchardetected is True:
		encoder_default_value = ''.join([random.choice(alpha) for _ in range(8)])
		print "Bad Character Detected. Using new value for encoder ..."
		print "New encoder default value used: " + encoder_default_value
		print "============================================="

print "============================================="
print "Shellcode Success!"


