import socket
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('server.pem', 'server.key')

#proxy
proxy_ip = "172.16.1.1"
proxy_port = 8081

#endpoint
server_host = "93.184.216.34"
server_port = 443


with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((proxy_ip, proxy_port))
    sock.listen(1)
    print("Man-in-the-middle proxy listening on {}:{}".format(proxy_ip, proxy_port))

    with context.wrap_socket(sock, server_side=True) as ssl_sock:
        client_sock, addr = ssl_sock.accept()

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


        client_sock.close()
        server_sock.close()
        print('Communication ended.')