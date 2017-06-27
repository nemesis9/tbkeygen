import unittest

from tbnumerics import tbnumerics

"""
To run: from one level above this file:
   
```
    python -m tests.test_tbnumerics_unittest -v

```
"""

class TestTbNumerics(unittest.TestCase):

    def setUp(self):
        self.tbn = tbnumerics()
        pass

    def test_factor_powers_of_p_392_10(self):
        lst = self.tbn.factor_powers_of_p(392, 10)
        self.assertListEqual(lst, [3, 9, 2])

    def test_factor_powers_of_p_16_2(self):
        lst = self.tbn.factor_powers_of_p(16, 2)
        self.assertListEqual(lst, [1, 0, 0, 0, 0])
            
    def test_factor_powers_of_p_38_3(self):
        lst = self.tbn.factor_powers_of_p(38, 3)
        self.assertListEqual(lst, [1, 1, 0, 2])
 
    def test_factor_is_prime_31(self):
        b = self.tbn.is_prime(31)
        self.assertEqual(b, True)

    def test_gen_prime_ceil_100(self):
        p = self.tbn.gen_prime_ceil(100)
        self.assertEqual(self.tbn.is_prime(p), True)
        self.assertGreater(100, p)
       

    def tearDown(self):
        pass


if __name__ == '__main__':
    unittest.main()
