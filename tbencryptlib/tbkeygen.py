import sys
import random
from . import tbnumerics

'''
  Credits
  Abstract Algebra: Theory and Applications
  Thomas W. Judson
  http://abstract.ups.edu/aata/index.html

  Number Theory
  George E. Andrews
  ISBN: 0-486-68252-8

  Handbook of Applied Cryptography, by A. Menezes, P. van
  Oorschot, and S. Vanstone, CRC Press, 1996.
  For further information, see www.cacr.math.uwaterloo.ca/hac

'''

class tbkeygen:
    def __init__(self, _bits=1024, _verbose=False, _debug=False):
        self.MOD_PREFIX = "MODULE tbencryptlib::tbkeygen"
        self.DEBUG = _debug
        self.VERBOSE = _verbose

        '''initialize key parameters and bits'''
        self.p1 = 0
        self.p2 = 0
        self.E = 0
        self.D = 0
        self.N = 1
        self.bits = _bits
        '''instantiate a numerics class'''
        if self.VERBOSE:
            self.numerics = tbnumerics.tbnumerics(True)
        else:
            self.numerics = tbnumerics.tbnumerics()

    '''
        PUBLIC
    '''

    def generate_keypair_from_primepair(self, p1, p2):
        ent = 0.0
        N = p1*p2
        E = 0
        rsa_phi = (p1-1)*(p2-1)

        # At this point, rsa_phi = (p-1)(q-1)
        coprime = False

        while not coprime:
            E = self.numerics.gen_prime_ceil(rsa_phi)
            (gcd, x, y) = self.numerics.egcd_iter(E, rsa_phi)
            if 1 != gcd:
                sys.stderr.write(self.MOD_PREFIX + ":The random prime" +
                                 " generated is not coprime with phi, retry" + "\n")
                sys.stderr.write(self.MOD_PREFIX + "::generate_keypair_from_primepair:" +
                                "GCD(E, rsa_phi) NOT equal to 1: Equals: " + str(gcd) + "\n")
            else:
                coprime = True

        D = self.numerics.modinv(E, rsa_phi)

        if 1 != (D*E)%rsa_phi:
            sys.stderr.write(self.MOD_PREFIX + ":The computed private" +
                             " exponent is not the inverse of the public" +
                             " exponent modulus rsa_phi, retry")
            raise Exception(self.MOD_PREFIX + "::generate_keypair_from_primepair:" +
                             "D*E is NOT 1 mod rsa_phi")

        self.__verbose("::N = " + str(self.N))
        self.__verbose("::E = " + str(self.E))
        self.__verbose("::D = " + str(self.D))
        return(N, E, D)




    def generate_keypair(self):
        ent = 0.0
        # self.N = 1
        rsa_phi = 1

        '''
            the key length in bits is considered to be bit-length of the
            product of two primes.  The bit length of the product of two
            numbers is generally the sum of the bit lengths of the
            individual multiplicands.
        '''
        (rnd, ent) = self.numerics.gen_nbit_prime(self.bits/2 + 2)
        self.__verbose("Prime p: " + str(rnd) + '\n')
        self.p1 = rnd
        self.N = self.N*rnd
        rsa_phi = rsa_phi*(rnd-1)

        (rnd, ent) = self.numerics.gen_nbit_prime(self.bits/2 - 2)
        self.__verbose("Prime q: " + str(rnd) + '\n')
        self.p2 = rnd
        self.N = self.N*rnd
        rsa_phi = rsa_phi*(rnd-1)

        # At this point, rsa_phi = (p-1)(q-1)

        '''
            This is not necessarily how a 'standard' algorithm might
            generate the public exponent. Here, we take the number of
            1 bits in the rsa_n value and use it to generate a probable
            prime.  Should be good if the entropy was good, which it
            normally is, but we *could* add a check here
        # commonly used public exponent 65537
        # self.E = 65537
        '''
        one_bits = bin(self.N).count("1")
        (self.E,ent) = self.numerics.gen_nbit_prime(one_bits)

        if 1 != self.numerics.greatest_common_divisor(self.E, rsa_phi):
            sys.stderr.write(self.MOD_PREFIX + ":The random prime" +
                             " generated is not coprime with phi, retry")
            raise Exception(self.MOD_PREFIX + "::__generate_keypair:" +
                            "GCD(E, rsa_phi) NOT equal to 1")

        self.D = self.numerics.modinv(self.E, rsa_phi)

        if 1 != (self.D*self.E)%rsa_phi:
            sys.stderr.write(self.MOD_PREFIX + ":The computed private" +
                             " exponent is not the inverse of the public" +
                             " exponent modulus rsa_phi, retry")
            raise Exception(self.MOD_PREFIX + "::__generate_keypair:" +
                            "D*E is NOT 1 mod rsa_phi")

        self.__verbose("::N = " + str(self.N))
        self.__verbose("::E = " + str(self.E))
        self.__verbose("::D = " + str(self.D))

        result = self.test_keys()
        if False == result:
            self.__errprnt("::__generate_keypair:Tests failed for" +
                           "generated keys")
            raise Exception(self.MOD_PREFIX + "::__generate_keypair:" +
                            "Tests failed for generated keys, retry")


    def set_debug(self, b_dbg):
        if b_dbg:
            self.DEBUG = True
        else:
            self.DEBUG = False

    def set_verbose(self, b_vrb):
        if b_vrb:
            self.VERBOSE = True
        else:
            self.VERBOSE = False

    def get_public_keypair(self):
        self.__verbose("::returning: E:" + str(self.E) +
                       " N:" + str(self.N))
        return (self.E, self.N)

    def get_private_keypair(self):
        self.__verbose("::returning: D:" + str(self.D) +
                       " N:" + str(self.N))
        return (self.D, self.N)

    def get_primes(self):
        return (self.p1, self.p2)


    def test_keys(self):
        testnums = []
        for i in range(10):
            testnums.append(random.randint(32, 65535))

        for i, msg in enumerate(testnums):
            self.__verbose("\n\nTEST #" + str(i+1))
            enc = pow(msg, self.E, self.N)

            dec = pow(enc, self.D, self.N)

            if dec != msg:
                self.__verbose("TEST FAILED: encrypt of " +
                               str(msg) + " = " + str(enc) +
                               " decrypt of " + str(enc) +
                               " = " + str(dec))
                return False
            else:
                self.__verbose("TEST PASSED: encrypt of " +
                               str(msg) + " = " + str(enc) +
                               " decrypt of " + str(enc) +
                               " = " + str(dec))
            i = i+1

        return True


    '''
        PRIVATE
    '''

    def __dbgprnt(self,msg):
        if True == self.DEBUG:
            print(self.MOD_PREFIX + " DEBUG:" + msg)

    def __verbose(self,msg):
        if True == self.VERBOSE:
            print(self.MOD_PREFIX + ":" + msg)

    def __errprnt(self,msg):
            print(self.MOD_PREFIX + " ERROR: " + msg)


'''
 EOF
'''
