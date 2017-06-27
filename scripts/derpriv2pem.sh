#!/bin/bash

## the input is expected to be a PKCS1 DER-encoded private key file
## 

function usage()
{
    echo "Usage: der2pem infile.der outfile.pem"
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


openssl pkey -inform der -in $1 -outform pem -out $2 

