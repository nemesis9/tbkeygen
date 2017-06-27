import sys
import random
from random import SystemRandom
import math

'''Credits
  Abstract Algebra: Theory and Applications
  Thomas W. Judson
  http://abstract.ups.edu/aata/index.html

  Number Theory
  George E. Andrews
  ISBN: 0-486-68252-8

  Handbook of Applied Cryptography, by A. Menezes, P. van
  Oorschot, and S. Vanstone, CRC Press, 1996.
  For further information, see www.cacr.math.uwaterloo.ca/hac

  *** ROUTINES ***
  __is_probable_prime(self,n):
  factor_powers_of_p(self, n, p):
  factor_powers_of_two(self, n):
  prime_factors(self, n):
  egcd_iter(self, a, b)
  egcd(self, a, b)  ## recursive version
  greatest_common_divisor(self, a, b)
  modinv(self, a, m)
  is_prime(self, prime_candidate)
  gen_nbit_prime(self,nbits)
  gen_prime_ceil(self,ceil)
  next_multiple_of(self, num, blksize)
  sum_of_digits(self, _x)
'''

class tbnumerics:
    def __init__(self, _verbose=False, _debug=False):
        self.MOD_PREFIX = "MODULE tbencryptlib::tbnumerics"
        self._mrpt_num_trials = 5 # number of bases to test
        self.DEBUG = _debug
        self.VERBOSE = _verbose
        self.sysrandom = SystemRandom()

    '''
       PRIVATE
    '''

    def __dbgprnt(self,str):
        if True == self.DEBUG:
            sys.stdout.write(self.MOD_PREFIX + ":" +
                             str + '\n')

    def __verbose(self,str):
        if True == self.VERBOSE:
            sys.stdout.write(self.MOD_PREFIX + ":" +
                             str + '\n')

    def __errprnt(self,str):
            sys.stderr.write(self.MOD_PREFIX + "ERROR: " +
                             str + '\n')

    def __is_probable_prime(self,n):
        """
        Miller-Rabin primality test.

        A return value of False means n is certainly not prime. A return value of
        True means n is very likely a prime.
        """
        assert n >= 2
        # special case 2
        # we exclude 2, since it is not useful for key generation
        if n == 2:
            return False
        # ensure n is odd
        if n % 2 == 0:
            return False
        # write n-1 as 2**s * d
        # repeatedly try to divide n-1 by 2
        s = 0
        d = n-1
        while True:
            quotient, remainder = divmod(d, 2)
            if remainder == 1:
                break
            s += 1
            d = quotient
        assert(2**s * d == n-1)

        # test the base a to see whether it is a witness
        # for the compositeness of n
        def try_composite(a):
            if pow(a, d, n) == 1:
                return False
            for i in range(s):
                if pow(a, 2**i * d, n) == n-1:
                    return False
            return True # n is definitely composite

        for i in range(self._mrpt_num_trials):
            # a = random.randrange(2, n)
            a = self.sysrandom.randrange(2, n)
            if try_composite(a):
                return False

        return True # no base tested showed n as composite


    '''
       PUBLIC
    '''

    '''
       FACTORING

    '''
    def factor_powers_of_p(self, n, p):
        power_list = []
        '''
        start with rn = n
           find the highest possible exponent e
           go through the exponents less than e,
              the coefficient of each exponent is the quotient n//(p**e)
           go to the next lower e with the remainder n%(p**e)
        '''
        try:
            rn = int(n)
            rp = int(p)
        except:
            self.__errprnt("::factor_powers_of_p:inputs must be integer type")
            raise

        # find highest exponent
        e=0;
        while p**e <= n:
            e = e+1

        e = e-1
        while e:
             power_list.append(n//(p**e))
             n = n % (p**e)
             e = e - 1

        power_list.append(n)
        return power_list



    def factor_powers_of_two(self, n):
        power_list = []
        '''
        start with rn = n
          divide: let ri = rn/2 until ri becomes 1
           push the number of times divided onto the array
           test rx = rn - 2^i
            if this is: > 1 then let rn = rx
                         == 1 push 0 on the array and return
                         == 0 return
        '''
        try:
            rn = int(n)
        except:
            self.__errprnt("::factor_powers_of_two:input must be integer type")
            raise

        while rn>1:

            rx = int(rn)
            i=0
            while rx>1:

                ri = rx//2

                if ri >= 1:
                    i+=1
                    rx = ri
                    if rx==1:
                        power_list.append(i)
                        rn = rn - (2**i)

        if rn == 1:
            power_list.append(0)

        return power_list

    '''
       PRIME FACTORIZATION
    '''
    def prime_factors(self, n):
        i = 2
        factors = []
        while i * i <= n:
            if n % i:
                i += 1
            else:
                n //= i
                factors.append(i)
        if n > 1:
            factors.append(n)
        return factors

    '''
       PRIME FACTORIZATION 2
        start at the given i
    '''
    def prime_factors2(self, n, _i):
        ## i = 2
        i = _i
        factors = []
        while i * i <= n:
            if n % i:
                i += 1
            else:
                n //= i
                factors.append(i)
        if n > 1:
            factors.append(n)
        return factors




    '''
       EUCLIDEAN ALGORITHMS - iterative

       Extended Euclidean Algorithm
       iterative version
    '''
    def egcd_iter(self, a, b):
        x,y, u,v = 0,1, 1,0
        while a != 0:
            q, r = b//a, b%a
            m, n = x-u*q, y-v*q
            b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
        return gcd, x, y

    '''
       EUCLIDEAN ALGORITHM - recursive

       Extended Euclidean Algorithm
       the recursive version will blow the stack ("max recusion depth")
       with bit lengths of about 2048
    '''
    def egcd(self, a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    '''
       GREATEST COMMON DIVISOR

    '''
    def greatest_common_divisor(self, a, b):
        try:
            aint = int(a)
            bint = int(b)
        except:
            self.__errprnt("::greatest_common_divisor:inputs must be integer type")
            raise

        if a==b:
            return a
        if a>b:
            self.greatest_common_divisor(b, a)

        while True:
            rn = b%a
            if rn == 0:
                return a
            else:
                b=a
                a=rn

    '''
       MODULAR INVERSE

    '''
    def modinv(self, a, m):
        g, x, y = self.egcd_iter(a, m)
        if g != 1:
            raise Exception('tbencryptlib:tbnumerics::modinv:modular ' +
                            'inverse does not exist')
        else:
            return x % m


    '''
       IS_PRIME

    '''
    def is_prime(self, prime_candidate):

        try:
            pc = abs(int(prime_candidate))
        except:
            self.__errprnt('::is_prime:inputs must be integer type')
            raise

        if pc == 1:
            return False

        b = self.__is_probable_prime(pc)
        return b


    '''
       GEN_NBIT_PRIME

       Generate a prime such that the magnitude is a certain number of bits
    '''
    def gen_nbit_prime(self,nbits):

        try:
            inum = int(nbits)
        except:
            self.__errprnt("::gen_nbit_prime: " +
                           str(nbits) + " is not a number!")
            raise

        if inum == 0:
            raise Exception("tbnumerics:gen_nbit_prime: nbits is ZERO")

        #this seems kinda arbitrary, if caller wants pain go for it
        #if inum > 4096:
        #    raise Exception("tbencryptlib::gen_nbit_prime: Too many bits, should be less than or equal to 4096")
        lo = 2**(inum-1)
        hi = 2**(inum)
        self.__dbgprnt("gen_nbit_prime: gen prime between 0x" +
                       format(lo, '0x') + " and 0x" +
                       format(hi, '0x'))

        # rand_p = random.randint(lo, hi-1)
        rand_p = self.sysrandom.randint(lo, hi-1)
        while not self.__is_probable_prime(rand_p):
            if self.__is_probable_prime(rand_p):
                break
            else:
                if rand_p < hi-1:
                    rand_p += 1
                else:
                    # rand_p = random.randint(lo, hi-1)
                    rand_p = self.sysrandom.randint(lo, hi-1)


        one_bits = bin(rand_p).count("1")
        if float(one_bits) <= float(inum)/2.0:
            bit_entropy = float(one_bits)/float(inum)
        else:
            bit_entropy = (float(inum)-float(one_bits))/float(inum)

        self.__dbgprnt("Algorithm gen " + str(inum) + "-bit prime: 0x" +
                       format(rand_p, '0x') + " is prime: Entropy: " +
                       str(bit_entropy))

        return (rand_p, bit_entropy)


    '''
       GEN_PRIME_CEIL

       Generate a prime such that the magnitude is less than a certain number
    '''
    def gen_prime_ceil(self,ceil):
        nmin = 3
        try:
            inum = int(ceil)
        except:
            self.__errprnt("::gen_prime_ceil: " +
                           str(ceil) + " is not a number!")
            raise

        if inum < nmin:
            raise Exception("tbnumerics:gen_prime_ceil: ceil is too small")

        #this seems kinda arbitrary, if caller wants pain go for it
        #if inum > 4096:
        #    raise Exception("tbencryptlib::gen_nbit_prime: Too many bits, should be less than or equal to 4096")
        ## lo = 2**(inum-1)
        hi = inum
        self.__dbgprnt("gen_prime_ceil: gen prime less than 0x" + format(hi, '0x'))

        # rand_p = random.randint(nmin, hi-1)
        rand_p = self.sysrandom.randint(nmin, hi-1)
        while not self.__is_probable_prime(rand_p):
            if self.__is_probable_prime(rand_p):
                break
            else:
                if rand_p < hi-1:
                    rand_p += 1
                else:
                    # rand_p = random.randint(nmin, hi-1)
                    rand_p = self.sysrandom.randint(nmin, hi-1)

        return rand_p

    '''
        BLOCK ENCRYPTION ROUTINES
        the next number after num that is a even multiple of blksize
    '''
    def next_multiple_of(self, num, blksize):
        b_num = 0
        b_blk = 0
        try:
            b_num = int(num)
            b_blk = int(blk)
        except:
            return 0

        return b_num + (b_blk-b_num%b_blk)


    '''
       SUNDRY UTILS
    '''
    def sum_of_digits(self, _x):
        x = 0
        try:
            x = int(_x)

        except:
            print("sum_of_digits: _x must be integer")
            return -1

        total = 0
        xs = str(x)
        for c in xs:
            total += int(c)

        return total

    '''
       BIT LENGTH OF A NUMBER
    '''
    def bit_length(self, _x):
        x = 0
        try:
            x = int(_x)

        except:
            print("sum_of_digits: _x must be integer")
            return -1

        return math.ceil(math.log(x, 2))

    '''
        DEBUGGING
    '''
    def set_debug(self, b_dbg):
        if True == b_dbg:
            self.DEBUG = True
        else:
            self.DEBUG = False

    def set_verbose(self, b_vrb):
        if True == b_vrb:
            self.VERBOSE = True
        else:
            self.VERBOSE = False

'''
 EOF
'''
