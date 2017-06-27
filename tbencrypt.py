#!/usr/bin/env python3
# coding=utf-8
import sys
import numbers
import math
import random
import tbencryptlib
from tbencryptlib import tbkeygen
from tbencryptlib import tbnumerics
import argparse
from collections import OrderedDict

'''
#Credits
  Abstract Algebra: Theory and Applications
  Thomas W. Judson
  http://abstract.ups.edu/aata/index.html

  Number Theory
  George E. Andrews
  ISBN: 0-486-68252-8

  Handbook of Applied Cryptography, by A. Menezes, P. van
  Oorschot, and S. Vanstone, CRC Press, 1996.
  For further information, see www.cacr.math.uwaterloo.ca/hac


 a*b mod m = [(a mod m)(b mod m)] mod m
 (a+b) mod m = [(a mod m) + (b mod m)] mod m

  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  HEADER byte: enumerated 1-8
   8 7 6 5 4 3 2 1

   8-7 = Classification bit
   6 = Constructed bit
   5-1 = Primitive type

   Classification:  # Mostly a "side-band" piece of info
     Bit8   Bit7   Class
      0      0     Universal
      0      1     Application
      1      0     Context Specific
      1      1     Private

 ASN.1 Header Byte
 8-7 = classification we will use 00
 6   = Constructed bit - for sequences and sets
 5-1 = Primitive type
'''

LSB_MASK = 0xff
CONSTRUCT_MASK = 0x20

ASN1_TYPES = {"BOOLEAN"            : 1,
              "INTEGER"            : 2,
              "BIT STRING"         : 3,
              "OCTET STRING"       : 4,
              "NULL"               : 5,
              "OBJECT IDENTIFIER"  : 6,
              "SEQUENCE"           : 16,
              "SEQUENCE OF"        : 16,
              "SET"                : 17,
              "SET OF"             : 17,
              "PrintableString"    : 19,
              "IA5String"          : 22,
              "UTCTIME"            : 23
             }


'''
   Print a byte array
'''
def print_ba(byar):
    ## sys.stdout.write("bytearray:")
    print("print_ba: Length of array: " + str(len(byar)))
    for i in range(len(byar)):
        val = byar[i]
        sys.stdout.write("%02X" % val)

    sys.stdout.write("\n")


'''
   Retrieve the most significant byte of a value
'''
def msb(i):
    print("msb: start val: " + str(hex(i)))
    a = bin(i)
    print("msb: start bin: " + str(a[0:10]) + "  length: " + str(len(a)-2))
    xl = len(a)
    ''' a would be a string like 0b101001... '''
    '''    we need to insert 0's (after the 0b) until the binary representation '''
    '''    contains a number of bits that is a multiple of 8 '''
    while (xl - 2)%8 != 0:
        a = a[:2] + "0" + a[2:]
        xl = len(a)

    print("msb: fixup bin: " + str(a[0:10]))
    b = a[2:10]    ## get the first EIGHT bits of the value, skip the 0b
    c = int(b,2)
    d = bin(c)
    print("msb: final bin: " + str(d[0:10]))
    return c


'''
   Write DER encoded data to file
'''
def write_der(fname, barray):
    with open(fname, "wb") as f:
        f.write(barray)

    f.close()


'''
   Print routine
'''
def asn1_print(msg, ktype):
    print("ASN.1 ENCODE " + str(ktype) + ": " + msg)



'''
   These will contain the DER encoded bytes
'''
ba = bytearray()
ba_public = bytearray()


'''
   keydata filled in by gen_keypair
'''
keydata = OrderedDict([
           ("coefficient"       , None),
           ("exponent2"         , None),
           ("exponent1"         , None),
           ("prime2"            , None),
           ("prime1"            , None),
           ("privateExponent"   , None),
           ("publicExponent"    , None),
           ("modulus"           , None),
           ("version"           , None)
          ])


'''
   encode_asn1

    - generate private or public DER file
    -
    - Assume the keydata dictionary contains the values
      to be encoded and populate the appropriate bytearray
'''
def encode_asn1(private=True):
    global keydata
    global ba
    global ba_public
    ka = None
    bytes_needed = 0
    print("Encode ASN.1")
    total_length = 0
    KTYPE = ""
    zero_prepend = False ## if most signifcant bit is 1 for a positive integer, then prepend 0x00 byte
    ## in python 3, items not iteritems

    if private:
        lst = ["version", "modulus", "publicExponent", "privateExponent", "prime1",
             "prime2", "exponent1", "exponent2", "coefficient"]
        KTYPE = "PRIVATE"
        ka = ba
    else:
        lst = ["modulus", "publicExponent"]
        KTYPE = "PUBLIC"
        ka = ba_public


    for k,v in keydata.items():

        if k in lst:

            asn1_print("\n***FIELD: " + str(k) + "           Val: " + str(hex(v)), KTYPE)
            val = v
            ## These numbers are all positive so if the MSB has its most sig bit set
            ##       then we need to prepend a zero byte
            MSB = msb(val)
            if MSB > 0x7f:
                zero_prepend = True
            else:
                zero_prepend = False

            ## Handle the special case of a zero value (version)
            if 0 == val:
                bytes_needed = 1
                asn1_print("val = 0, inserting byte: " + str(bytes_needed), KTYPE)
                ka.insert(0, 0)
            else:
                bytes_needed = int(math.ceil(math.log(val, 256)))
                asn1_print("val > 0, bytes_needed: " + str(bytes_needed), KTYPE)
                i = 0
                asn1_print("inserted bytes : " + str(hex(val)), KTYPE)
                while val:
                    ## push LSB's first
                    ka.insert(0, val&0xff)
                    val = val >> 8
                    i = i+1

                asn1_print("inserted " + str(hex(i)) + " bytes", KTYPE)
                if zero_prepend:
                    asn1_print("insert zero prepend: bytes", KTYPE)
                    bytes_needed += 1
                    ka.insert(0, 0x00)

            ## Length byte
            if bytes_needed < 128:
                lb = 0x7f&bytes_needed
                asn1_print("insert length byte (short) : " + str(hex(lb)), KTYPE)
                ka.insert(0, lb)
            else:
                if 0 == bytes_needed%256:
                    bytes_needed += 1
                length_bytes_needed = int(math.ceil(math.log(bytes_needed, 256)))
                lb = 0x80|length_bytes_needed
                for i in range(length_bytes_needed):
                    asn1_print("insert length extra byte (long) : " + str(hex(bytes_needed&0xff)), KTYPE)
                    ka.insert(0, bytes_needed&0xff)
                    bytes_needed = bytes_needed >> 8

                asn1_print("insert length byte (long) : " + str(hex(lb)), KTYPE)
                ka.insert(0, lb)

            ## Header byte (these are all INTEGER)
            ka.insert(0, 0x02)  ## Universal, not constructed, Integer

    ## Sequence
    asn1_print("\n\nEncode ASN.1:  ENCODE SEQUENCE:", KTYPE)
    total_length = len(ka)
    seq_byte =  0x20 | 0x10
    if total_length < 128:
        lb = 0x7f&len(ka)
        asn1_print("SEQ length byte (short) : " + str(hex(lb)), KTYPE)
        ka.insert(0, lb)
    else:
        bytes_needed = int(math.ceil(math.log(total_length, 256)))
        if 0 == total_length%256:
            bytes_needed += 1
        asn1_print("SEQ Length bytes needed: " + str(bytes_needed), KTYPE)
        lb = 0x80|bytes_needed
        asn1_print("SEQ length byte (long) : " + str(hex(lb)), KTYPE)
        for i in range(bytes_needed):
            asn1_print("SEQ long encoded byte #: " + str(i) + " : " + str(hex(total_length&0xff)), KTYPE)
            ka.insert(0, total_length&0xff)
            total_length = total_length >> 8

        ka.insert(0, lb)

    ka.insert(0, seq_byte)
    total_length = len(ka)
    asn1_print("Total length: " + str(total_length), KTYPE)
    asn1_print("ASN.1  byte array: Length:" + str(len(ka)) + " ", KTYPE)
    print_ba(ka)

    asn1_print("**** END ****", KTYPE)



def gen_keypair(bits):
    numerics = tbkeygen.tbnumerics.tbnumerics()

    try:
        keygen = tbencryptlib.tbkeygen.tbkeygen(bits, False)
        keygen.generate_keypair()

        sys.stdout.write("RESULTS:\n")
        (p1, p2) = keygen.get_primes()
        sys.stdout.write("Prime 1: " + str(hex(p1)) + '\n')
        sys.stdout.write("Prime 2: " + str(hex(p2)) + '\n')
        (E, N) = keygen.get_public_keypair()
        sys.stdout.write("Public Modulus   N: " + str(hex(N)) + '\n')
        sys.stdout.write("Public Exponent  E: " + str(hex(E)) + '\n')
        (D, N) = keygen.get_private_keypair()
        sys.stdout.write("Private Exponent D: " + str(hex(D)) + '\n\n')

        ## Populate keydata
        keydata['version'] = 0
        keydata['modulus'] = N
        keydata['publicExponent'] = E
        keydata['privateExponent'] = D
        keydata['prime1'] = p1
        keydata['prime2'] = p2
        keydata['exponent1'] = D%(p1-1)
        keydata['exponent2'] = D%(p2-1)
        keydata['coefficient'] = numerics.modinv(p2, p1)

        #encode the private
        encode_asn1()
        #encode the public
        encode_asn1(False)
        write_der("tbprivate.der", ba)
        write_der("tbpublic.der", ba_public)

    except Exception as e:
        sys.stdout.write("Exception during keygen: " + str(e) + '\n')
        sys.exit(1)




'''
   run_tests

   choose a key bit-length from a list, generate keypair and
     test encryption with that key

'''
def run_tests():
    bits_select = [64, 128, 256, 512, 1024, 2048]

    while 1:
        s = random.randint(0,len(bits_select)-1)
        desired_bits = bits_select[s]

        keygen = tbencryptlib.tbkeygen.tbkeygen(desired_bits, True, False)
        keygen.generate_keypair()

        sys.stdout.write("\n\nTEST PARAMETERS for next 10 tests: (bits=" + str(desired_bits) + ")\n")
        (E, N) = keygen.get_public_keypair()
        sys.stdout.write("Public Exponent: " + str(E) + '\n')
        (D, N) = keygen.get_private_keypair()
        sys.stdout.write("Private Exponent: " + str(D) + '\n')
        sys.stdout.write("N: " + str(N) + '\n\n')

        #Tests - encrypt, decrypt

        testmsgs = []
        for i in range(10):
            testmsgs.append(random.randint(32, 65535))

        for msg in testmsgs:
            enc = pow(msg, E, N)
            print ("Encryption of " + str(msg) + " yields: " + str(enc))

            dec = pow(enc, D, N)
            print ("Decryption of " + str(enc) + " yields: " + str(dec))

            if dec != msg:
                print ("FAILED: encrypt of " + str(msg) + " = " + str(enc) + " decrypt of " + str(enc) + " = " + str(dec))
                sys.exit(1)
            else:
                #print ("PASSED: encrypt of " + str(msg) + " = " + str(enc) + " decrypt of " + str(enc) + " = " + str(dec))
                print("TEST PASSED!")





'''
   parse_own_args

'''
def parse_own_args(args):
    if args[1] != '-r' and args[1] != '-g':
        usage()
    elif args[1] == '-r':
        return('-r', None)
    elif args[1] == '-g' and len(args) < 3:
        usage()
    elif args[1] == '-g' and len(args) > 2:
        return ('-g', args[2])
    else:
        return (None, None)

'''
   usage

'''
def usage():
    print("tbencrypt {-r | -g bits}, where:")
    print("            -r=run tests")
    print("            -g=generate keys with 'bits' length")
    print("  bits should be a large power of 2")
    sys.exit(1)


'''
   main

   processes options from command line
   -r : generate keys of various lengths and run tests until Ctrl-C.
                         bits arg is ignored in this case
   -g : generate a 'bits' length key and generate DER encoded
                          public and private key files
'''
def main():
    global keydata
    print("Encrypt main: start")
    try:
        (argopt, argbits) = parse_own_args(sys.argv)
    except Exception as e:
        print(str(sys.argv[0]) + ": Parse args failed: " + str(e))
        usage()

    if argopt == None:
       usage()

    if argopt =='-r':
        print("-r option")
        run_tests()

    elif argopt =='-g':
        try:
            bits = int(argbits)
        except Exception as e:
            print(str(sys.argv[0]) + ": Parse args failed: " + str(e))
            usage()


        print("-g option with " + str(bits) + " bits")
        gen_keypair(bits)

    else:
        print("An option is required")
        usage()


if __name__ == "__main__":
    main()


####
## ASN.1 : standard for encoding and representing common data types
## Spec is ITU-T X.680
## For encryption, supports BER, CER, DER
##     BER: Basic Encoding Rules
##     CER: Canonical Encoding Rules
##    DER: Distinguished Encoding Rules
#3
## Sidenote: PEM is Base64-encoded DER
## The three rule-sets encode the same ASN.1 types the same way;
## They differ in the rules used for field length, Boolean, etc
##
## BASICS
##     Name ::= type
##       "Name" is an instance of a given ASN.1 type called "type"
##       Example : MyName ::= IA5String
##          means "MyName" is of type IA5String (like an ASCII string)
##
## EXPLICIT VALUES
##  Name ::= type (Explicit Value)
##     Example: MyName ::= IA5String (Tom)
##         means MyName is the IA5String encoding of "Tom"
##     Example: MyName ::= (Tom|Joe)
##        MyName is "Tom" or "Joe"
##
## CONTAINERS (SEQUENCE OR SET types)
##    Four container types: SEQUENCE, SEQUENCE OF, SET, SET OF
##
##    Grammar: Name ::= Container { Name Type [ Name Type ...] }
##
##    Containers can nest and can be written on multiple lines:
##
##        Name ::= Container {
##            Name Container {
##               Name Type,
##              [Name Type, ...]
##            },
##            [Name Type, ...]
##        }
##
##
##  Container Example:
##    UserRecord ::= SEQUENCE {
##      Name SEQUENCE {
##          First IA5String
##          Last  IA5String
##      },
##      DOB UTCTIME
##   }
##
## MODIFERS: OPTIONAL, DEFAULT, CHOICE
##
##  OPTIONAL:
##    Name ::= Type OPTIONAL
##  This can be a problem in containers, such as
##    Float ::= SEQUENCE {
##       Exponent INTEGER OPTIONAL,
##       Mantiss  INTEGER,
##       Sign     BOOLEAN
##    }
## The decoder MUST be able to habdler this.  If the exponent is missing, the decoder will need to
##     figure that out, usually by look-ahead reads.
##
## DEFAULT:  If the value is absent, then use the default.
##
## CHOICE:  A datatype may be one or abother type
##    Example:
##        UserKey ::= SEQUENCE {
##           Name       IA5STRING,
##           StartDate  UTCTIME,
##           Expire     UTCTIME,
##           KeyData   CHOICE {
##              ECCKey    ECCKeyType,
##              RSAKey    RSAKeyType,
##           }
##        }
##
##  The decoder must be able to determine which choice was made during encoding
##  ########################
##  Data Types:  (These are not all types, but sufficient for encryption code, meaning PKCS #1 and ANSI X9.62)
##
##    - Boolean
##    - OCTET String
##    - BIT String
##    - IA5String
##    - PrintableString
##    - INTEGER
##    - OBJECT Identifier (OID)
##    - UTCTIME
##    - NULL
##    - SEQUENCE,SEQUENCE OF
##    - SET, SET OF
##
##  Encodings for these data types consist of:
##   HEADER Byte
##   LENGTH Encoding (two methods of encoding)
##   PAYLOAD
##  ############################
##
##  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
##  HEADER byte: enumerated 1-8
##   8 7 6 5 4 3 2 1
##
##   8-7 = Classification bit
##   6 = Constructed bit
##   5-1 = Primitive type
##
##   Classification:  # Mostly a "side-band" piece of info
##     Bit8   Bit7   Class
##      0      0     Universal
##      0      1     Application
##      1      0     Context Specific
##      1      1     Private
##
##      Universal is most common
##
##   Constructed bit: indicates whether encoding is a construction
##                    of multiple sub-encodings of the same type.
##       With the DER, the only constructed types are the container
##          types.  The bit is zero otherwise
##
##
##   The lower five bits specify one of 32 ASN.1 primitives
##
##    1        Boolean Type                Store Booleans
##    2        INTEGER                     Store large integers
##    3        BIT STRING                  Store an array of bits
##    4        OCTET STRING                Store an array of bytes
##    5        NULL                        Place holder (e.g., in a CHOICE)
##    6        OBJECT IDENTIFIER           Identify algorithms or protocols
##    16       SEQUENCE and SEQUENCE OF    Container of unsorted elements
##    17       SET and SET OF              Container of sorted elements
##    19       PrintableString             ASCII Encoding (omitting several non-printable chars)
##    22       IA5STRING                   ASCII Encoding
##    23       UTCTIME                     Time in a universal format
##  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
##
##  LENGTH Encodings
##    ASN.1 specifies two methods of encoding depending on the actual length of the element
##     Bit 8    = Long encoding bit
##     Bit 7-1  = Immediate length
##
##    Short encodings (bit 8 = 0)
##        length is less than 128 bytes
##        bits 7-1 indicate length directly
##
##        Example: length is 65 bytes (0x41)
##        LENGTH byte is 0x41
##
##    Long encodings (bit 8 = 1)
##        length is 128 bytes or more
##        bits 7-1 DO NOT indicate length directly
##        Instead indicates number of bytes of length
##
##        Example: length is 47310 bytes (0xB8CE)
##        LENGTH is encoded as 0x82 0XB8 0xCE
##        0x82 means long encoding with 2 bytes for length
##        0xB8 0XCE indicate length is 47310 bytes
##
##        In DER practice:
##            - all 1s byte (127) is not valid
##            - long-encoded lengths of more than 4 bytes
##                 are not valid, since that would represent more than
##                 4GB of storage.
##
##
##   BOOLEAN Encodings
##       Value of Boolean    Encoding           Note
##         False             0x01 01 00         01 = Boolean  01 = Length 00 = False
##         True              0x01 01 FF         01 = Boolean  01 = Length FF = True
##
##
##   INTEGER Encodings
##       Represents signed arbitrary precision
##       Numbers are represented as byte-sized digits 256^k*Xk + 256^k-1*Xk-1 + ... 256^0*X0
##
##       Octets are stored in descending order, positive numbers must have most significant
##         bit of first byte = 0
##
##
##
##
##  PKCS #1 Key Format
##
##  PKCS #1 specifies two key formats for RSA keys; one is meant for public keys, and the other is meant for private keys. The public key format is the following.
##
##  RSAPublicKey ::= SEQUENCE {
##      modulus           INTEGER, - n
##      publicExponent    INTEGER, - e
##
##  While the private key format is the following.
##
##  RSAPrivateKey ::= SEQUENCE {
##      version           Version,
##      modulus           INTEGER, - n
##      publicExponent    INTEGER, - e
##      privateExponent   INTEGER, - d
##      prime1            INTEGER, - p
##      prime2            INTEGER, - q
##      exponent1         INTEGER, - d mod (p-1)
##      exponent2         INTEGER, - d mod (q-1)
##      coefficient       INTEGER, - (1/q) mod p
##      otherPrimeInfos   OtherPrimeInfos OPTIONAL
##  }
##  Version ::= INTEGER { two-prime(0), multi(1) }
##  OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
##  OtherPrimeInfo ::= SEQUENCE {
##      prime         INTEGER, - ri
##      exponent      INTEGER, - di, d mod prime
##      coefficient   INTEGER, - ti
##  }
##
##
##
