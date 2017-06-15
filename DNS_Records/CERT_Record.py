from dns.resolver import query as dig
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class CERT_Record(object):

    def __init__(self, domain):
        self.certificates = list()  # [(base64cert, x509cert), ...]
        self.base64certs = list()
        self.x509certs = list()

        try:
            answer = dig(domain, "CERT")
        except:
            return

        for rdata in answer:
            # PKIX 27305 RSASHA256 MIIFUjCCBDqgAwIBAgIQD4+rEpeKOMyt ....
            response = str(rdata).split(" ")

            base64cert = "".join(response[3:])
            certificate = "\n".join(["-----BEGIN CERTIFICATE-----"]+[base64cert]+["-----END CERTIFICATE-----"])
            x509cert = x509.load_pem_x509_certificate(certificate, default_backend())

            self.base64certs.append(base64cert)
            self.x509certs.append(x509cert)
            self.certificates.append((base64cert, x509cert))

# # # #


if __name__ == "__main__":
    direct_domain = CERT_Record('direct.aahs.org')
    for cert in direct_domain.x509certs:
        # https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Extensions
        for ext in cert.extensions:
            if ext.critical:
                if type(ext.value) is x509.KeyUsage:
                    for key_usage in ["digital_signature", "content_commitment"]:
                        print getattr(ext.value, key_usage)
                print(ext.value)