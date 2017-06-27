#!/bin/bash

## the input is expected to be a PKCS1 DER-encoded public key file
##  

function usage()
{
    echo "Usage: encrypt.sh plain.txt pubkey.pem cipher.txt"
    echo "       where plain.txt and pubkey.pem are inputs and cipher.txt is output"
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


openssl rsautl -in $1 -encrypt -pubin -inkey $2 -out $3 


