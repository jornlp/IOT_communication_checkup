import sys
from socket import socket

from OpenSSL import SSL, crypto

# https://www.codeproject.com/Tips/1278114/Python-3-How-to-Download-View-and-Save-Certificate
def get_certificate(host, port, cert_file_pathname):
    s = socket()
    context = SSL.Context(SSL.TLSv1_2_METHOD)
    print('Connecting to {0} to get certificate...'.format(host))
    conn = SSL.Connection(context, s)
    certs = []

    try:
        conn.connect((host, port))
        conn.do_handshake()
        certs = conn.get_peer_cert_chain()

    except SSL.Error as e:
        print('Error: {0}'.format(str(e)))
        exit(1)

    try:
        for index, cert in enumerate(certs):
            cert_components = dict(cert.get_subject().get_components())
            cn = (cert_components.get(b'CN')).decode('utf-8')
            print('Centificate {0} - CN: {1}'.format(index, cn))

            try:
                temp_certname = '{0}_{1}.crt'.format(cert_file_pathname, index)
                with open(temp_certname, 'w+') as output_file:
                    output_file.write((crypto.dump_certificate
                                         (crypto.FILETYPE_PEM, cert).decode('utf-8')))

            except IOError:
                print('Exception:  {0}'.format(IOError.strerror))

    except SSL.Error as e:
        print('Error: {0}'.format(str(e)))
        exit(1)


get_certificate("93.184.216.34", 443, "ok.crt")



