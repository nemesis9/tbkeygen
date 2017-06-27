tbkeygen generates PKI-compatible keypairs.
These can be used with ssh.

The purpose of this project is that I wanted to
see how it all works.

The main python script is tbencrypt.py

It is dependent upon tbencryptlib, which consists of:
  - tbkeygen.py
  - tbnumerics.py

tbnumerics is a standalone numerics library which contains
routines for general number theory usage.

tbencrypt has two modes of usage.
1. tbencrypt.py -r 
   Generate keypairs of bit lengths chosen from a list
   and test encryption using them.  This runs continuously,
   Ctrl-C to stop it.

2 tbencrypt.py -g <bits>
  Example: tbencrypt.py -g 1024

  This will generate a 1024 bit keypair and produce
  an ASN.1 encoded keypair.  By default, these are
  tbprivate.der and tbpublic.der
  Note they are DER encoded.



Then use scripts/derpriv2pem.sh and scripts/derpub2pem.sh to convert these to PEM files
    scripts/derpriv2pem.sh tbprivate.der tbprivate.pem
    scripts/derpub2pem.sh tbpublic.der tbpublic.pem

Then use scripts/encrypt.sh and scripts/decrypt.sh to test encryption and decryption.
    ## Create a clear text file
    vi clear.txt   //put some text you want to encrypt in clear.txt

    ## encrypt it to cipher.txt
    scripts/encrypt.sh clear.txt tbpublic.pem cipher.txt
 
    ## decrypt back to plain text
    scripts/decrypt.sh cipher.txt tbprivate.pem decrypted.txt

    ## diff clear.txt decrypted.txt
    ## Should be no differences

    Note there is a limit in openssl about how much data it will encrypt,
    as public/private keypairs are not normally used on large datasets.

Generate ssh compatible keys for client and server machines.
    # Generate the id_rsa file for ~/.ssh/
    openssl rsa -in tbprivate.pem -out id_rsa
    # Generate the id_rsa.pub file for ~/.ssh/authorized_keys
    openssl rsa -in tbprivate.pem -RSAPublicKey_out -out id_rsa.pub

    append id_rsa.pub to authorized_keys file.
 

    




