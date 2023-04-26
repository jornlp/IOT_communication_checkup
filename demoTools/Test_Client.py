import socket

hostname = "www.example.com"
port = 80
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((hostname, port))

request = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(hostname)
sock.sendall(request.encode())

response = sock.recv(4096)

print(response.decode())

sock.close()