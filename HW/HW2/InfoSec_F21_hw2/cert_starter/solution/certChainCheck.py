'''
This program is used to validate if a certain target domain has a chain of valid certifcates.
The program does not have a built in CRL method, which should be cautious about
Note: the program should be run with python3, and all required libraries should be referred to requirement.txt
Date:10/06/2021
Author: Future Hacker Mr. Pico
'''


#!/usr/bin/python3

from OpenSSL import SSL,crypto
import socket
import OpenSSL
import certifi
import pem
import fnmatch
import urllib
import re

# Cert Paths
TRUSTED_CERTS_PEM = certifi.where()

def get_cert_chain(target_domain):
    '''
    This function gets the certificate chain from the provided
    target domain. This will be a list of x509 certificate objects.
    '''
    # Set up a TLS Connection
    dst = (target_domain.encode('utf-8'), 443)
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    s = socket.create_connection(dst)
    s = SSL.Connection(ctx, s)
    s.set_connect_state()
    s.set_tlsext_host_name(dst[0])

    # Send HTTP Req (initiates TLS Connection)
    s.sendall('HEAD / HTTP/1.0\n\n'.encode('utf-8'))
    s.recv(16)
    
    # Get Cert Meta Data from TLS connection
    test_site_certs = s.get_peer_cert_chain()
    s.close()
    
    return test_site_certs

############### Helper Functions Below
#read CA file from known path. Take each certificate and load them into the root certificate store sequentially
def load_root_ca(store):
    
    with open(TRUSTED_CERTS_PEM) as f:
        cacert = f.read()
        pattern = re.compile("# Issuer:[\S\s]*?-----END CERTIFICATE-----") #Match the pattern of each certificate
        matches = pattern.findall(cacert)     
        for match in matches:       
            root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, match)       
            store.add_cert(root_cert)
##############################################

def x509_cert_chain_check(target_domain: str) -> bool:
    '''
    This function returns true if the target_domain provides a valid 
    x509cert and false in case it doesn't or if there's an error.
    '''
    store = OpenSSL.crypto.X509Store() 
    load_root_ca(store)  
    cert_chain = get_cert_chain(target_domain)
    leaf_crt = cert_chain.pop(0)
    
    # Verify all intermediate certificates
    try:
        for inter_med in reversed(cert_chain):          
            store_ctx = OpenSSL.crypto.X509StoreContext(store,inter_med)
            store_ctx.verify_certificate()
            store.add_cert(inter_med)
        
        # Verify Leaf Certificate
        store_ctx = OpenSSL.crypto.X509StoreContext(store,leaf_crt)
        store_ctx.verify_certificate()    
        
        # Check if the "valid" leaf certificate falls into the edge case: 
        # i.e. hello.pandu.xyz.com should not be considered as *.xyz.com
        extension = ''
        for i in range(leaf_crt.get_extension_count()):               
                extension += str(leaf_crt.get_extension(i)) #Combine all crt extension info in extension string
        
        pattern = re.compile("DNS:\*[a-z\.-]*") #Extract all DNS starting with *
        matches = pattern.findall(extension)     
        for domain_name in matches:
            domain_name = domain_name.lstrip("DNS:*") # e.g.For "DNS:*.google.com", it will be converted to ".google.com"
            if domain_name in target_domain:
                prefix = target_domain.split(domain_name)[0]
                if "." in prefix:
                    continue
                else:
                    return True
        return False
    except Exception as e:
        print(e)
        return False
    
    


if __name__ == "__main__":
    # Standalone running to help you test your program
    print("Certificate Validator...")
    target_domain = input("Enter TLS site to validate: ")
    print("Certificate for {} verifed: {}".format(target_domain, x509_cert_chain_check(target_domain)))
