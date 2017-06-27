
## this only seems to work with a private key file, not public key file

function usage()
{
    echo "Usage: pem2der infile.pem outfile.der"
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

openssl rsa -inform pem -in $1 -outform der -out $2
