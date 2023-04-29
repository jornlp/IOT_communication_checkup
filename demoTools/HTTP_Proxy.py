import socket

#proxy
proxy_ip = "127.0.0.1"
proxy_port = 8080

#endpoint
server_host = "93.184.216.34"
server_port = 80

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind((proxy_ip, proxy_port))
    sock.listen(1)
    print("Man-in-the-middle proxy listening on {}:{}".format(proxy_ip, proxy_port))

    client_sock, client_addr = sock.accept()
    print("{} connected".format(client_addr[0], client_addr[1]))

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.connect((server_host, server_port))
    print("Connected to server {}:{}".format(server_host, server_port))

    while True:
        client_data = client_sock.recv(4096)
        if not client_data:
            break
        print(client_data)
        server_sock.sendall(client_data)
        print("Data sent to server.")

        server_data = server_sock.recv(4096)
        if not server_data:
            break
        print(server_data)
        client_sock.sendall(server_data)
        print("Data sent to client.")

    server_sock.close()
    client_sock.close()
    print('Communication ended.')