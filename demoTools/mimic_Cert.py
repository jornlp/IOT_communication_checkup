import ssl


def fetch_server_certificate(dns_name, port):
    """Fetch the server certificate from the given dns_name and port
    @param dns_name: The dns name to fetch the certificate for
    @param port: The port that is serving the certificate
    @return: X509 certificate object
    """
    pem_server_certificate = ssl.get_server_certificate((dns_name, port))
    with open("test.pem", 'w') as f:
        f.write(pem_server_certificate)
    x509_server_certificate = pem_to_x509(pem_server_certificate)
    return x509_server_certificate


fetch_server_certificate("www.example.org", 443)