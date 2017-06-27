#!/bin/bash

## the input is expected to be a PKCS1 DER-encoded public key file
##  

function usage()
{
    echo "Usage: decrypt.sh cipher.txt privkey.pem plain.txt"
    echo "       where cipher and privkey.pem are inputs and plain.txt is output"
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

if [ -z "$3" ]
then 
    usage
fi


openssl rsautl -in $1 -decrypt -inkey $2 -out $3 


