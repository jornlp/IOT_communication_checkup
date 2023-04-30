import os
from socket import socket

from OpenSSL import SSL, crypto

import ssl
import OpenSSL.crypto

current_dir = os.getcwd()

print(current_dir)
folder_path = os.path.join(current_dir, 'trustedCerts')


def get_certificates(host, port):
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

    # Convert all certificates in the chain to the desired format
    converted_certs = []

    for cert in certs:
        converted_certs.append(cert)

    return converted_certs


def getRootX509(allCerts):
    rootCert = ''
    highestCert = allCerts[0]
    for filename in os.listdir(trustedCerDir):
        if filename.endswith(".pem"):
            with open("%s%s" % (trustedCerDir, filename), 'rb') as f:
                cert = f.read()
            file_to_check = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

            if highestCert.get_issuer() == file_to_check.get_issuer():
                rootCert = file_to_check
    return rootCert


allCerts = get_certificates("www.example.org", 443)
rootCert = getRootX509(allCerts)
print(rootCert)