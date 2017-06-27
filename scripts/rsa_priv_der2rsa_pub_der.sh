

## Takes a RSAPrivateKey (PKCS#1) formatted DER file
##   and converts to RSAPublicKey formatted DER file

## This can be used to validate the output of tbencrypt.py

function usage()
{
    echo "Usage: rsa_priv_der2rsa_pub_der rsa_infile.der rsa_outfile.der"
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


openssl rsa  -inform DER -in $1 -pubout -outform DER -RSAPublicKey_out -out $2
 
