#!/usr/bin/python

#only compatible with python 2.x

import binascii
import os
import re
import shutil
import argparse

def extract_keys(loader):
	"""
	Attempt to extract possible keys
	"""
	contents = loader.read()
	
	#key typically appears near the callout string
	#obtain offset of the beginning of the callout string
	offset = contents.find("http")
	
	#extract data within 1000 bytes before and after the offset of the callout string
	minimum = offset - 1000
	maximum = offset + 1000
	key_range = contents[minimum:maximum]
	
	#regex to extract potential keys
	expression = re.compile('\x00\x00(?P<key>\w{3,})\x00+')
	
	#obtain all matches within the defined range
	keys = expression.findall(key_range)
	print("Potential keys discovered:")
	print(keys)
	return keys

def create_buffer():
	"""
	Create initial 256-byte buffer
	"""
	ammyy_buffer = []
	i = 0
	while i < 256:
		ammyy_buffer.append("0x{:02x}".format(i)[-2:])    
		i += 1
	return ammyy_buffer 

def attempt_decryption(ammyy_path, ammyy_buffer, keys):
	"""
	Attempt to decrypt ammyy
	"""
	for i in keys:
		shutil.copyfile(str(ammyy_path), "decrypted.txt")
		ammyy = open("decrypted.txt", "r+b")
		print("Attempting decryption with key: " + str(i))

		#utilize the key to prepare the buffer
		modified_buffer = prepare_buffer(ammyy_buffer, str(i))
	
		#utilize the new buffer to attempt decryption
		decrypt_ammyy(modified_buffer, ammyy, ammyy_path)

		#ensure we are at the beginning of the file
		ammyy.seek(0, 0)

		#check the first two bytes of the decrypted file with the PE magic number
		if str(binascii.hexlify(ammyy.read()[:2])) == "4d5a":
			print("Decryption Successful!")
			ammyy.close()
			break
		else:
			print("Key Failed! Trying next.")
			ammyy.close()
			os.remove("decrypted.txt")

def prepare_buffer(ammyy_buffer, key):
	"""
	Manipulate buffer for use in decryption
	"""
	#copy buffer to maintain original
	modified_buffer = ammyy_buffer[:]
	#loop counter
	BL = 0
	#stores arithmetic byte from previous loop
	DH = 0
	#key offset
	key_offset = 0
	#key size
	key_size = len(key) - 1

	#loop over each byte in the buffer
	while BL < 256:
	    #read a byte from the bufer
	    #each loop iterates to the next byte in the buffer
		DL = modified_buffer[BL]

		#read a byte from the key
		#each loop iterates to the next byte in the key
		EAX = key[key_offset]

		#add the key and buffer byte
		EAX = int(DL, 16) + int(binascii.hexlify(EAX), 16)

		#each iteration's result is added together and stored in DH
		DH += EAX
		
		#DH should only be one byte
		#we confirm this by converting to hex and stripping last two characters
		#convert back to int for arithmetic
		DH = int("0x{:02x}".format(DH)[-2:], 16)

		#read byte from buffer at offset DH
		EAX = binascii.hexlify(modified_buffer[DH])

		#write byte to buffer at offset corresponding to the loop counter
		#the byte written is the byte read from the buffer at offset DH
		modified_buffer[BL] = binascii.unhexlify(EAX)

		#write byte to buffer at offset DH
		#the byte written is the byte read from the buffer at the beginning of the loop
		modified_buffer[DH] = DL

		#once the last byte is read, start over with the first byte
		if key_offset < key_size:
			key_offset += 1
		else:
			key_offset = 0

		#increment loop counter
		BL += 1
	return modified_buffer 

def decrypt_ammyy(modified_buffer, ammyy, ammyy_path):
	"""
	Utilize the buffer to decrypt ammyy
	"""
	#length of encrypted file
	ammyy_length = os.path.getsize(ammyy_path)
	#buffer offset
	BH = 0
	#loop counter
	EDI = 0
	#stores arithmetic value from previous loop
	DL = 0

	#loop over each byte in the encrypted sample
	while EDI < ammyy_length:

		#buffer is 256 bytes
		#once the last byte is read, start over with the first byte
		if BH < 255:
			BH += 1
		else:
			BH = 0

		#read a byte from the bufer
	    #each loop iterates to the next byte in the buffer
		BL = modified_buffer[BH]

		#add DL to the buffer byte
		DL = DL + int(BL, 16)
		
		#DL should only be one byte
		#we confirm this by converting to hex and stripping last two characters
		#convert back to int for arithmetic
		DL = int("0x{:02x}".format(DL)[-2:], 16)

		#read byte from buffer at offset DL
		ECX = modified_buffer[DL]

		#write previously read byte to buffer
		#offset (BH) increments with loop iteration
		modified_buffer[BH] = ECX

		#write byte to buffer at offset DL
		#the byte written is the byte read from the buffer at the beginning of the loop
		modified_buffer[DL] = BL

		#read byte from buffer
		#offset (BH) increments with loop iteration
		EDX = modified_buffer[BH]

		#add EDX to the byte read from the buffer at the beginning of the loop
		EDX = int(BL, 16) + int(EDX, 16)

		#AND EDX 255
		EDX = EDX & 255

		#read byte from buffer at offset EDX
		ECX = modified_buffer[EDX]

		#read a byte from the encrypted sample
	    #each loop iterates to the next byte in the sample
		ammyy.seek(EDI, 0)
		ammyy_byte = ammyy.read(1)

		#XOR ECX with the byte read from the encrypted sample
		ECX = int(binascii.hexlify(ammyy_byte), 16) ^ int(ECX, 16)
		#format ECX for writing
		ECX = "0x{:02x}".format(ECX)
		
		#write decrypted byte to the sample
		#ECX should only be one byte
		#we confirm this by converting to hex and stripping last two characters
		ammyy.seek(EDI, 0)
		ammyy.write(binascii.unhexlify(ECX[-2:]))

		#increment loop counter
		EDI += 1

if __name__ == "__main__":
	#parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument('-a', required=True, action = "store", dest = "ammyy", help = "provide the path to the encrypted ammyy sample")
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument('-k', action = "store", dest = "key", help = "pass the key for decryption")
	group.add_argument('-l', action = "store", dest = "loader", help = "provide the path to the unpacked loader")

	results = parser.parse_args()

	#set ammyy path
	ammyy_path = results.ammyy

	#if key is not provided, extract from loader
	if results.key is None:
		loader_path = results.loader
		loader = open(loader_path, "r+b")
		keys = extract_keys(loader)
		loader.close()
	else:
		keys = [results.key]

	ammyy_buffer = create_buffer()
	attempt_decryption(ammyy_path, ammyy_buffer, keys)