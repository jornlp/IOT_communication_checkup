# https://rileymacdonald.ca/2019/01/24/python-write-tcp-proxy-inspection-fuzzing/

import sys
import socket
import threading


def server_loop(local_host, local_port, remote_host, remote_port):
    # Define a server socket to listen on
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Bind the socket to the defined local address and port
        server.bind((local_host, local_port))
    except:
        print("[!!] Failed to connect to {}:{}".format(local_host, local_port))
        print("[!!] Check for other listening sockets or correct")
        sys.exit(0)

    print("Successfully listening on {}:{}".format(local_host, local_port))
    sys.stdout.flush()

    server.listen(5)

    # Loop infinitely for incoming connections
    while True:
        # will only trigger when connection is made
        client_socket, addr = server.accept()

        print(client_socket, addr)
        sys.stdout.flush()

        print("[==>] Received incoming connection from {}:{}".format(addr[0], addr[1]))
        sys.stdout.flush()

        # Start a new thread for any incoming connections
        proxy_thread = threading.Thread(target=proxy_handler,
                                        args=(client_socket, remote_host, remote_port))
        proxy_thread.start()


# def main():
#
#
#     # if len(sys.argv[1:]) != 5:
#     #     print("Usage: python tcp_proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]")
#     #     print("Example: python tcp_proxy 127.0.0.1 21 target.host.ca 21 True")
#     #     sys.exit(0)
#
#     # Store the arguments
#     local_host = sys.argv[1]
#     local_port = int(sys.argv[2])
#     remote_host = sys.argv[3]
#     remote_port = int(sys.argv[4])
#
#     # connect and receive data before sending to the remote host?
#     receive_first = sys.argv[5]
#
#     if "True" or "true" in receive_first:
#         receive_first = True
#     else:
#         receive_first = False
#
#     # Start looping and listening for incoming requests (see implementation below)
#     server_loop(local_host, local_port, remote_host, remote_port, receive_first)


def proxy_handler(client_socket, remote_host, remote_port):
    # Define the remote socket used for forwarding requests
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Establish a connection to the remote host
    remote_socket.connect((remote_host, remote_port))

    # intercept the response before it's received
    # if receive_first:
    #     # receive data from the connection and return a buffer
    #     remote_buffer = receive_from(remote_socket)
    #
    #     # Convert the buffer from hex to human readable output
    #     hexdump(remote_buffer)
    #
    #     # Handle the response (an opportunity for read/write of the response data)
    #     remote_buffer = response_handler(remote_buffer)
    #
    #     # If data exists send the response to the local client
    #     if len(remote_buffer):
    #         print("[<==] Sending {0} bytes from localhost".format(len(remote_buffer)))
    #         client_socket.send(remote_buffer)

    # Continually read from local, print the output and forward to the remotehost
    while True:
        # Receive data from the client and send it to the remote
        local_buffer = receive_from(client_socket)
        send_data(local_buffer, "localhost", remote_socket)

        # Receive the response and sent it to the client
        remote_buffer = receive_from(remote_socket)
        send_data(remote_buffer, "remotehost", client_socket)

        # Close connections, print and break out when no more data is available
        if not len(local_buffer):
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Connections closed")
            break


def send_data(buffer, type, socket):
    if len(buffer):
        print("[<==] Received {0} bytes from {1}.".format(len(buffer), type))
        hexdump(buffer)

        if "localhost" in type:
            mod_buffer = request_handler(buffer)
        else:
            mod_buffer = response_handler(buffer)

        socket.send(mod_buffer)

        print("[<==>] Sent to {0}".format(type))


def receive_from(connection):
    buffer = ""

    # use a 2 second timeout
    connection.settimeout(2)

    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except:
        pass
    return buffer


def response_handler(buffer):
    print("response_handler: {}".format(buffer))
    return buffer


def request_handler(buffer):
    print("request handler: {}".format(buffer))
    return buffer


def hexdump(src, length=16):
    result = []
    digits = 4 if isinstance(src, str) else 2

    for i in range(0, len(src), length):
        s = src[i:i + length]
        hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
        result.append(b"%04X   %-*s   %s" % (i, length * (digits + 1), hexa, text))
    print(b'\n'.join(result))
