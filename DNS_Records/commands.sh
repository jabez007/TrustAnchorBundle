echo "-----BEGIN CERTIFICATE-----;$(dig CERT $directDomain +short | cut -d " " -f4- | tr " " "\n");-----END CERTIFICATE-----" | tr ";" "\n"