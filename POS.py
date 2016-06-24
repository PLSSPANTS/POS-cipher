#Written in python 2.7.9
def Letter_Hex(letter):
	letter=hex(ord(letter))[2:]
	if len(letter) is 1:
		letter="".join(("0",letter))
	return letter
def Str_Hex(Str):
	return "".join(Letter_Hex(letter) for letter in Str)
def Chr_Bin(letter):
	r=bin(ord(letter))[2:]
	r="0"*(8-len(r))+r
	return r
def Hex_Str(Hex):
	if "L" in Hex:
		Hex=Hex[:-1]
	if len(Hex)%2 is not 0:
		Hex="0"+Hex
	index=range(0,len(Hex),2)
	return "".join(chr(int(Hex[letter:letter+2],16)) for letter in index)
def Str_Int(Str):
	return int(Str_Hex(Str),16)
def Round(n,l):
	return n%(int("ff"*l,16))

def Int_Str(Int):
	return Hex_Str(hex(Int)[2:])

class POS:
	"""Class object for the Primitive Obfuscation Standard cipher, or POS for short.

As a stream cipher, there is no set block-size. Optimally, ciphertext must be decrypted in the same sized blocks as it was encrypted.

On initialization, the given key is saved both into POS.key and POS.run. Encryption starts with key generation, and will continue until POS.run is at least the length of the given plaintext. Every key generation is numbered, and the number is modulated by the length of POS.key, and adds the byte at the resulting index of the key to every byte in the key. Every byte is also added with 1+x, where x is the index of each byte. (Note: all arithmetic performed on bytes is modulated by 256.) POS.key becomes the result and is added to POS.run.

The next step of encryption includes simple substitution and transposition rounds. Substitution simply adds the key bytes and state bytes. The eight rounds of transposition each take the corresponding bits in each byte of the key to produce a binary key. The first round takes the first bits, and the second take the second bits, and so on. Bytes in the state corresponding to 1 bits are rotated amongst themselves backward, and bytes corresponding to 0 are rotated forward. The bytes are rotated B times, where B is the number of the transposition round (1 to 8).

Encryption puts the state through a total of nine substitution rounds and eight transposition rounds. The cipher is indeed slow, untested, and ridiculously simple. Even if it's only for texts you don't want your great great grandparents to decipher, use this cipher with discretion. Remember: "Primitive Obfuscation Standard" is not only a contrast to AES, it's a backronym for POS.

"""
	def __init__(self,key):
		self.gen=0
		self.key=key
		self.run=key
		l=len(key)
	def transposition(self,state,key):
		"""Performs the eight transposition rounds and nine substitution rounds. This is called by the encrypt() method."""
		state=list(state)
		for b in range(8):
			state=list(self.substitution(state,key))
			binary=list(Chr_Bin(letter)[b] for letter in key)
			ON=[]
			OFF=[]
			for digit in range(len(binary)):
				if binary[digit] == "1":
					ON.append(digit)
				else:
					OFF.append(digit)
			b+=1
			if b>=len(ON):
				try:
					b1=b%len(ON)
				except ZeroDivisionError:
					b1=0
			else:
				b1=b
			if b>=len(OFF):
				try:
					b0=b%len(ON)
				except ZeroDivisionError:
					b0=0
			else:
				b0=b
			ON=ON[b1:]+ON[:b1]
			OFF=OFF[-b0:]+OFF[:-b0]
			indices=[]
			for digit in binary:
				if digit =="1":
					indices.append(ON.pop(0))
				else:
					indices.append(OFF.pop(0))
			state=list(state[index] for index in indices)
		return "".join(self.substitution(state,key))
	def reposition(self,state,key):
		"""Inverse of transpotion function. Performs the eight reposition rounds and nine constitution rounds. This is called by the decrypt() method."""
		state=list(state)
		for b in range(7,-1,-1):
			state=list(self.constitution(state,key))
			binary=list(Chr_Bin(letter)[b] for letter in key)
			ON=[]
			OFF=[]
			for digit in range(len(binary)):
				if binary[digit] == "1":
					ON.append(digit)
				else:
					OFF.append(digit)
			b+=1
			if b>=len(ON):
				try:
					b1=b%len(ON)
				except ZeroDivisionError:
					b1=0
			else:
				b1=b
			if b>=len(OFF):
				try:
					b0=b%len(ON)
				except ZeroDivisionError:
					b0=0
			else:
				b0=b
			ON=ON[-b1:]+ON[:-b1]
			OFF=OFF[b0:]+OFF[:b0]
			indices=[]
			for digit in binary:
				if digit =="1":
					indices.append(ON.pop(0))
				else:
					indices.append(OFF.pop(0))
			state=list(state[index] for index in indices)
		return "".join(self.constitution(state,key))
	def keygen(self):
		"""Alters the key into a block to add to the running key. Called by the encypt() and decrypt() methods."""
		self.gen+=1
		gen=self.gen%len(self.key)
		key=list(ord(letter) for letter in self.key)
		for x in range(len(key)):
			key[x]+=key[gen]+(x+1)
			key[x]%=256
		self.key="".join(chr(letter) for letter in key)
		self.run="".join([self.run,self.key])
	def substitution(self,state,key):
		"""Simple substitution round. Called by the transposition() method."""
		return "".join(chr((ord(state[x])+ord(key[x]))%256) for x in range(len(state)))
	def constitution(self,state,key):
		"""Inverse of the substitution() method. Called by the reposition() method."""
		return "".join(chr((ord(state[x])-ord(key[x]))%256) for x in range(len(state)))
	def encrypt(self,plaintext):
		"""Encrypts the given plaintext."""
		while len(self.run)<len(plaintext):
			self.keygen()
		key=self.run[:len(plaintext)]
		self.run=self.run[len(plaintext):]
		return self.transposition(plaintext,key)
	def decrypt(self,ciphertext):
		"""Decrypts the given plaintext."""
		while len(self.run)<len(ciphertext):
			self.keygen()
		key=self.run[:len(ciphertext)]
		self.run=self.run[len(ciphertext):]
		return self.reposition(ciphertext,key)
