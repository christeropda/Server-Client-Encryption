from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
import socket
import time
import sys
import os

class ComunicationHandler():
    def __init__(self, host, port):
        self.host = host 
        self.port = port
        self.requestdict = {
            "picture1": "GET /picture.jpg",
            "video1": "GET /video.mp4"
        }
    
    def send_request(self, key, sock):
        """
        checks if key recieved from prompt exist,
        if certificates dont exist certificates are created,
        connects to host and port and sends request to server
        """
        #check if input key exist in the dictionary
        if not key in self.requestdict:
            print("*that file does not exist")
            print("key given: ", key)
            exit()
        #open the keys, if it does not exist make a key pair
        try:
            with open('public_key.pem', 'rb') as infile:
                public_key = RSA.importKey(infile.read())
            infile.close()
        except:
            self.create_keyset()
            with open('public_key.pem', 'rb') as infile:
                public_key = RSA.importKey(infile.read())
            infile.close()

        #connecting to the server
        sock.connect((self.host, self.port))
        
        #convert dictionary to byte and concatinate the dictionary(Get string), key and encryption type 
        byte_path = self.str_to_byte(key)
        data = self.concatinate_message(byte_path, public_key)

        #sending the concatinated message
        sock.sendall(data)

    def recieve(self, socket):
        """
        will recieve data until it has recieved the total amount, 
        total amount declared in the first recieved 16 bytes
        """
        totaldata = []
        #recieve the size of the data 
        sizeoffile = socket.recv(16)
        length = 0

        #recieve while we have not recieved all data
        while length < int(sizeoffile):    
            data = socket.recv(8192)
            
            if len(data) > 0:
                print("writing..........................")
                totaldata.append(data)
            
            length += len(data)
        
        socket.close()

        #join the list and return
        todecrypt = b''.join(totaldata)
        
        return todecrypt
                
    def decrypt_key_rsa(self, key):
        """
        decrypts a given key
        """
        #get the private key to decrypt
        with open('private_key.pem', 'rb') as infile:
            private_key = RSA.importKey(infile.read())
        infile.close()

        #decrypting
        dec_key = private_key.decrypt(key)
        
        return dec_key

    def decrypt_file_aes(self, key, data):
        """
        decrypts the encrypted file recieved
        """
        read = 16
        chunk_size = 64*1024
        output_name = "(deckrypted)"+self.formating

        #write the data into a file, makes it easier to read the data
        with open('temp', 'wb') as infile:
            infile.write(data)
        infile.close()

        #reading the temp data
        with open('temp', 'rb') as infile:
            text_size = int(infile.read(read))
            IV = infile.read(read)

            de_cryptor = AES.new(key, AES.MODE_CBC, IV)
            print("decrypting")
            #decrypting into a new file with the given name 
            with open(output_name, 'wb') as outfile:
                while True:
                    chunk = infile.read(chunk_size)

                    if len(chunk) == 0:
                        break

                    outfile.write(de_cryptor.decrypt(chunk))
                outfile.truncate(text_size)
        #remove the temp file
        os.remove("temp")
        print("done...")

    
    def create_keyset(self):
        """
        creates a new RSA keyset
        """
        key = RSA.generate(1024)

        private_key = key.exportKey()
        public_key = key.publickey().exportKey()

        with open('private_key.pem', 'wb') as outfile:
            outfile.write(private_key)
        outfile.close()

        with open('public_key.pem', 'wb') as outfile:
            outfile.write(public_key)
    
    def str_to_byte(self, key):
        """
        converts the dictionary value mapped to the specified key into bytes
        """
        #making the dictionary into a sendable binary form and concatenating
        string = self.requestdict[key]
        string_to_bytes = string.encode()
        
        #setting the filename
        format0 = string_to_bytes.split(b"/")
        self.formating = format0[1].decode()

        return string_to_bytes
        

    def concatinate_message(self, path, public_key):
        """
        concatinate path and public key
        """
        #making the dictionary into a sendable binary form and concatenating
        #concatinating message to send, get message + public key + encryption type
        #adding two newlines to keep the public key intact after parsing in the server
        data = path+b'\n\n'+public_key.exportKey('PEM')

        return data

    def run(self):
        """
        main function of the program,
        calls the nessesary methods and passes in input
        """
        print("-----------list of possible files to be recieved/downloaded-----------")
        print("-----------             enter (Q) to exit                  -----------\n\n")
        for element in self.requestdict:
            print("     *", element)

        filename = input("\n\nsend a request for a file, filename must be same as one of the above: ")
        
        if filename == "Q":
            exit()

        #creating a socket 
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        #sending a concatinated request based upon the input.
        self.send_request(filename, sock)

        #calling the recieve function, returns all recieved data in a bytestring
        to_dec = self.recieve(sock)

        #parsing the returned data to separate key and file
        findkey = to_dec.split(b"\n\n\n\n")
        
        #decrypting the key and using key to decrypt file
        dec_key_rsa = self.decrypt_key_rsa(findkey[0])
        self.decrypt_file_aes(dec_key_rsa, findkey[1])
        os.remove("private_key.pem")
        os.remove("public_key.pem")

        self.run()

if __name__ == "__main__":
    host = input("Host: ")
    com = ComunicationHandler(host, 8084)
    com.run()

