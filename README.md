# Advanced-Encryption-Standard-in-C

Software Implementation of AES based on (FIPS) 197 in C.

Implementation is based on hardware implementation and corresponding FIPS specifications. 

# Source Code

aes.h has all the source code for encryption and decryption for all key lengths 128, 192, & 256.

aes2.h is the same but calls the print_cs and print_rk, so you can see the output of the key schedule and the state at each round.

main.c is executed to run all test cases.

# Testing

aes_test.h has the acceptance tests for encryption and decryption with all key lengths. 

cipherkey is used to test the key expansion (see main).

Results are printed to simple HTML file (see screen shot). 

# Environment

IDE Xcode Version 10.3 (10G8)

Darwin 18.7.0 Darwin Kernel Version 18.7.0: Tue Jun 22 19:37:08 PDT 2021; root:xnu-4903.278.70~1/RELEASE_X86_64 x86_64
