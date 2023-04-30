import os
from socket import socket

from OpenSSL import SSL, crypto

import ssl
import OpenSSL.crypto

current_dir = os.getcwd()
parent_dir = os.path.dirname(current_dir)
trustedCerDir = os.path.join(parent_dir, 'trustedCerts/')

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

    return certs


def getRootX509(allCerts):
    rootCert = ''
    highestCert = allCerts[-1]
    for filename in os.listdir(trustedCerDir):
        if filename.endswith(".pem"):
            with open("%s%s" % (trustedCerDir, filename), 'rb') as f:
                cert = f.read()
            file_to_check = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

            if highestCert.get_issuer() == file_to_check.get_issuer():
                rootCert = file_to_check

    return rootCert

def verifyCerts(certs, rootCert):
    results = []


    print(certs[-1].get_issuer(), certs[-1].get_subject())

    # self signed ontvangen?
    if (certs[-1].get_issuer() == certs[-1].get_subject()) and (rootCert != ''):
        # verify self signed certificate certs[-1]
        test = certs[-1].verify(rootCert.get_pubkey())
        if test == False:
            results.append("selfsignedfailed")
            return results
        certs.pop(-1)

    store = OpenSSL.crypto.X509Store()
    try:
        store.add_cert(rootCert)
    except:
        results.append("/")
        return results

    for cert in reversed(list((certs))):
        # print(cert.get_issuer().CN)
        store_ctx = OpenSSL.crypto.X509StoreContext(store, cert)

        try:
            results.append(store_ctx.verify_certificate())
        except:
            results.append("Invalid cert")
        store.add_cert(cert)
    return results


allCerts = get_certificates("www.example.org", 443)
rootCert = getRootX509(allCerts)
res = verifyCerts(allCerts, rootCert)


print(res)