#!/usr/bin/env python3
# Jonathan De Leon
# CSCI 531 Applied Cryptography
# April, 2021

import sys
import random
import math
import json

sys_random = random.SystemRandom()

# Default rounds to 40 due to following stack overflow
# https://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
def miller_rabin_primality(number, rounds=40):
    # Even numbers, other than 2 are composite
    if number == 2:
        return True
    if not number & 1:
        return False

    k, exp = 0, number - 1
    while not exp & 1: # exponent is not odd
        k += 1
        exp >>= 1 #  bit-wise right shift - divide by 2

    def check_primality(a, exp, k, n):
        x = pow(a, exp, n) # a**exp % number
        if x == 1:
            return True
        for i in range(k-1):
            if x == n - 1:
                return True
            x = pow(x, 2, n)
        return x == number - 1
    
    for round in range(rounds):
        a = sys_random.randrange(2, number - 1)
        if not check_primality(a, exp, k, number):
            return False

    return True


def test_prime(number):
    return miller_rabin_primality(number)


# use SystemRandom to generate a random number with x bits and test it for primeness
def generate_prime(bits):
    found = False
    while not found:
        number = sys_random.randrange(2**(bits-1), 2**bits)
        if test_prime(number):
            found = True
    return number


# find an `e` which is co-prime or relatively prime to phi
# Note: Two integers are co-prime if the only positive integer that divides them is 1
def find_coprime(phi, bits):
    found = False
    while not found:
        e = sys_random.randrange(2**(bits-1), 2**bits)
        if math.gcd(e, phi) == 1:
            found = True
    return e


# Adapted the extendended Euclidean algorithm for modular integers
# Note: not computing the Bezout coefficient
def extended_gcd(a, n):
    d, new_d = 0, 1
    r, new_r = n, a
    while new_r != 0:
        quotient = r // new_r
        d, new_d = new_d, d - quotient * new_d
        r, new_r = new_r, r - quotient * new_r
    # to get a positive number
    if d < 0:
        d += n
    return d


# find d such that e*d = 1 mod modulus
def compute_modular_inverse(e, modulus):
    if math.gcd(e, modulus) != 1:
        raise AssertionError('Modular inverse does not exist')
    return extended_gcd(e, modulus)


def generate_keys(bits=1024):
    print ('-'*20+' Generating p prime '+'-'*20)
    p = generate_prime(bits)
    # print ('p prime: %s' % p)
    print ('-'*20+' Generating q prime '+'-'*20)
    q = generate_prime(bits)
    # print ('q prime: %s' % q)
    n = p * q

    print ('*'*20+' Computing keys '+'*'*20)
    phi = (p-1) * (q-1)
    e = find_coprime(phi, bits)
    # print ('e prime: %s' % e)
    d = compute_modular_inverse(e, phi)
    # print ('e mod inverse: %s' % d)

    public_key = { 'e': e, 'n': n }
    private_key = { 'd': d, 'n': n }
    return (public_key, private_key)

if __name__ == "__main__":
    public, private = generate_keys()
    # print('Public: %s' % str(public))
    # print('Private: %s' % str(private))

    if len(sys.argv) > 1:
        user_name = sys.argv[1]
        print('Creating output files', user_name + '.pub', user_name + '.prv')
        with open(user_name + '.pub', 'w') as f:
            f.write(json.dumps(public))
        with open(user_name + '.prv', 'w') as f:
            f.write(json.dumps(private))