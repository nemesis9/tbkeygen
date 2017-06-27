#!/bin/bash

## the input is expected to be a PKCS1 DER-encoded public key file
##  

function usage()
{
    echo "Usage: derpub2pem infile.der outfile.pem"
    exit 1
}

if [ -z "$1" ]
then 
    usage
    exit 1
fi
 
if [ -z "$2" ]
then 
    usage
fi


openssl rsa -inform DER -RSAPublicKey_in -in tbpublic.der -outform PEM -out tbpublic.pem
