# RSA Public Key Cryptography

This C program contains code for a key generator, producing public and private key pairs,
an encryptor, encrypting files using a public key, and a decryptor, decrypting encrypted
files using the corresponding private key. The computations behind these processes are based
on the RSA crypto-system.

## Formatting

```
make format
```

## Building

```
make all
```

## Running

```
$ ./keygen [-hv] [-b bits] [-n pbfile] [-d pvfile]
```

```
OPTIONS
  -b : specifies the minimum bits needed for the public modulus n
  -i : specifies the number of Miller-Rabin iterations for testing primes (default: 50)
  -n pbfile : specifies the public key file (default: rsa.pub)
  -d pvfile : specifies the private key file (default: rsa.priv)
  -s : specifies the random seed for the random state initialization (default: the seconds since 
the UNIX epoch, given by time(NULL))
  -v : enables verbose output
  -h : displays program synopsis and usage
```

```
$ ./encrypt [-hv] [-i infile] [-o outfile] [-n pubkey]
```

```
OPTIONS
  -i : specifies the input file to encrypt (default: stdin)
  -o : specifies the output file to encrypt (default: stdout)
  -n : specifies the file containing the public key (default: rsa.pub)
  -v : enables verbose output
  -h : displays program synopsis and usage
```

```
$ ./decrypt [-hv] [-i infile] [-o outfile] [-n privkey]
```

```
OPTIONS
  -i : specifies the input file to decrypt (default: stdin)
  -o : specifies the output file to decrypt (default: stdout)
  -n : specifies the file containing the private key (default: rsa.priv)
  -v : enables verbose output
  -h : displays program synopsis and usage
```

## Cleaning

```
make clean
```

## Files

### decrypt.c
contains implementation and main() function for decrypt program

### encrypt.c
contains implementation and main() function for encrypt program

### keygen.c
contains implementation and main() function for keygen program

### numtheory.c
contains implementations of number theory functions

### numtheory.h
specifies interface for number theory functions

### randstate.c
contains implementation of random state interface for RSA library and num theory functions

### randstate.h
specifies interface for randstate functions

### rsa.c
contains implementation of RSA library

### rsa.h
specifies interface for RSA library

### Makefile
This file has all the commands to compile and clean the files

### DESIGN.pdf
This file contains information about the design/workflow of my randstate, numtheory, rsa, keygen, encrypt, and decrypt programs

### WRITEUP.pdf
This file contains a discussion of how I tested my individual function libraries as well as keygen, encrypt, and decrypt programs.

