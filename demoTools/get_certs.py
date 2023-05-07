import sys
from socket import socket

from OpenSSL import SSL, crypto
from cryptography.hazmat.primitives import serialization


# https://www.codeproject.com/Tips/1278114/Python-3-How-to-Download-View-and-Save-Certificate
def get_certificate(host, port):
    server = socket()
    context = SSL.Context(SSL.TLSv1_2_METHOD)
    print('Connecting to {0} to get certificate...'.format(host))
    conn = SSL.Connection(context, server)
    certs = []

    try:
        conn.connect((host, port))
        conn.do_handshake()
        certs = conn.get_peer_cert_chain()

    except SSL.Error as e:
        print('Error: {0}'.format(str(e)))
        exit(1)

    try:
        server_cert_chain = "server_cert_chain.pem"
        for index, cert in enumerate(certs):
            try:
                with open(server_cert_chain, 'a') as chain_file:
                    chain_file.write((crypto.dump_certificate
                                       (crypto.FILETYPE_PEM, cert).decode('utf-8')))
            except IOError:
                print('Exception:  {0}'.format(IOError.strerror))

    except SSL.Error as e:
        print('Error: {0}'.format(str(e)))
        exit(1)


get_certificate("93.184.216.34", 443)
