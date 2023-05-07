# https://robertheaton.com/2018/08/31/how-to-build-a-tcp-proxy-4/

# root met als naam issuer hoogste cert
# de rest custom aan de hand van info uit chain
from OpenSSL.crypto import (X509Extension, X509,
        dump_privatekey, dump_certificate,
        load_certificate, load_privatekey,
        PKey, TYPE_RSA, X509Req)
from OpenSSL.SSL import FILETYPE_PEM



# load in PEM closest to root
with open('example2.pem', 'rb') as f:
    cert_data = f.read()
    highest = load_certificate(FILETYPE_PEM, cert_data)

key = PKey()
key.generate_key(TYPE_RSA, 2048)

cert = X509()
cert.set_version(highest.get_version())
cert.set_serial_number(highest.get_serial_number())
cert.set_subject(highest.get_issuer())
cert.set_notBefore(highest.get_notBefore())
cert.set_notAfter(highest.get_notAfter())
cert.set_issuer(cert.get_subject())
cert.set_pubkey(key)

highest.get_extension_count()
highest.get_extension()
highest.add_extensions()

cert.sign(key, "sha256")

with open("customCerts/fakeCA.pem", 'wb+') as f:
    f.write(dump_certificate(FILETYPE_PEM, cert))

with open("customCerts/fakeCAKEY.pem", 'wb+') as f:
    f.write(dump_privatekey(FILETYPE_PEM, key))
