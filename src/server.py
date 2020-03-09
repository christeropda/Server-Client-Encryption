from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import socketserver
import sys
import os

class Server(socketserver.BaseRequestHandler):
	def handle(self):
		self.data = self.request.recv(1024).strip().decode("utf-8")
		print(self.data)

		#parsing and sending a response
		self.parse(self.data)
		self.response()

	def parse(self, data):
		#parsing the recieved data
		req = self.data.split("\n\n")
		self.reqtype = req[0].split(" ")
		self.filename = self.reqtype[1][1:]
		self.public_key = RSA.importKey(req[1])
		self.key = Random.new().read(16)

	def response(self):
		#encryption type AES:
		if self.reqtype[0] == "GET":
			#calling the encryption function
			#size = os.path.getsize(self.filename)

			if os.path.exists(self.filename):
				size = str(os.path.getsize(self.filename)).zfill(16)
				to_send = self.encrypt_aes(self.key, self.filename)

			#encrypting key before sending it 
			crypt_key = self.public_key.encrypt(self.key, 32)	

			#concatinating the key and the encrypted file to send
			#adding 4 newline characters because it is easier to parse with 4 of them.
			response = crypt_key[0]+b"\n\n\n\n"+to_send
			#sending the response
			self.request.sendall(size.encode())
			self.request.sendall(response)

	def encrypt_aes(self, key, filename):
		#setting the different sizes chunk/and read
		read_size = 16
		chunk_size = 64*1024
		#finding the filesize to get back to the original size after padding
		filesize = str(os.path.getsize(filename)).zfill(16)
		#creating vector
		IV = Random.new().read(16)  
		#creating the encryption matrix
		cryptor = AES.new(key, AES.MODE_CBC, IV)

		#list to append the encryted data to, since we are not making a file out of it.
		totaldata = []

		with open(filename, 'rb') as infile:
			#writing filesize and iv, both 16 bytes, since set sizes, its easy to read when decrypting
			totaldata.append(filesize.encode("utf-8"))
			totaldata.append(IV)
			#looping through the file, encrypting and adding the chunks to the list
			while True:
				chunk = infile.read(chunk_size)
				if len(chunk) == 0:
					break

				if (len(chunk) % read_size) != 0:
					chunk += b' '*(read_size-(len(chunk)%read_size))
				
				totaldata.append(cryptor.encrypt(chunk))
			
			#joining the items in the list after encryption befor returning
			to_send = b''.join(totaldata)
			return to_send
		


if __name__ == "__main__":
	try:
		HOST, PORT = 'localhost', 8084
		socketserver.TCPServer.allow_reuse_address = True
		server = socketserver.TCPServer((HOST, PORT), Server)
		server.serve_forever()
	except KeyboardInterrupt:
		server.shutdown()