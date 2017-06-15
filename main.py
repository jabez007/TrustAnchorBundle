import os
from cryptography.x509.oid import NameOID
import DNS_Records

SAVE_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "Trust Anchors")


if __name__ == "__main__":
    with open("direct addresses.txt", 'r') as address_file:
        address_list = [addr.strip() for addr in address_file.readlines()]

    domain_list = [addr.split("@")[1] for addr in address_list if len(addr.split("@")) > 1]

    for domain in domain_list:
        print(domain)
        domain_cert = DNS_Records.CERT_Record(domain)
        for cert in domain_cert.certificates:
            # https://cryptography.io/en/latest/x509/reference/#x-509-certificate-object
            base64cert = cert[0]
            issuer_common_name = cert[1].issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

            #print(base64cert)
            print(issuer_common_name)

            DNS_Records.export_cert_chain(base64cert, os.path.join(SAVE_DIR, issuer_common_name))
