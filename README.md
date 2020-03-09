Author: Christer H. Opdahl

This project explores server/client comunication as well as RSA and AES encryption.


#pip3

pip3 is needed to install pycrypto.
if not installed, run the next line in terminal
easy_install pip

linux users:
sudo apt-get install python3-pip

#pycrypto

install pycrypto library by running this in terminal:
pip3 install pycrypto

linux users need "sudo apt-get" in front of pip3 to make it work

#instruction

client and server are different prosesses and must be run indevidually.

run server by opening terminal in the folder and use "python3 server.py" to run
run client by opening terminal in the client folder and use "pyton3 client.py" to run

client will ask for host, enter "localhost" 
port is hardcoded to 8084 and server will serve on port 8084

client program will print available files to transfer, enter one of 
the filename printed when promted.


