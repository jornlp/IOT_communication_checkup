from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load the PEM certificate file
with open("example1.pem", "rb") as f:
    pem_data = f.read()

# Parse the certificate data
cert = x509.load_pem_x509_certificate(pem_data, default_backend())

# Extract the SAN extension, if present
san = None
for ext in cert.extensions:
    if isinstance(ext.value, x509.SubjectAlternativeName):
        san = ext.value
        break

# Print the results
if san:
    print("Subject Alternative Name (SAN):")
    for name in san:
        print(f"  {name}")
else:
    print("No Subject Alternative Name (SAN) extension found.")