#ifndef aes_128_h
#define aes_128_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>


/*
    Rijndael (AES) implementation based on FIP-197 standard.
 
    This the software implementation of my hardware implementation.
    It includes the encryption and decryption (the inverse cipher for practicality
    as opposed to the equivalent inverse cipher).
 
    By: Samira C. Oliva Madrigal
 
    test vectors from: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
*/

//test vector input for encryptio and decryption
unsigned char  plaintext[] = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";//same for all
unsigned char  key128[]  = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
unsigned char  key192[]  = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17";
unsigned char  key256[]  = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
unsigned char ciphertext128[]  = "\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a";
unsigned char ciphertext192[] = "\xdd\xa9\x7c\xa4\x86\x4c\xdf\xe0\x6e\xaf\x70\xa0\xec\x0d\x71\x91";
unsigned char ciphertext256[] = "\x8e\xa2\xb7\xca\x51\x67\x45\xbf\xea\xfc\x49\x90\x4b\x49\x60\x89";
//test vector input for key expansion unit testing
unsigned char cipher_key[] = "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";

//round constant word array
static const uint32_t Rcon[] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
};

static uint8_t Nb = 4; //number of state columns, always 4x4
uint8_t Nk = 4;//4; //count 32-bit of words trhat make up the key 4, 6, or 8
uint8_t Nr = 10;//10; //10, 12, or 14

/*------------------------------------------------------------------------
            PRINT CURRENT STATE IN COLUMN MAJOR ORDER
pre: state matrix of bytes
post: prints state in column major order as an array
 -------------------------------------------------------------------------*/
void print_cs(uint8_t **s)
{
    for(uint8_t i = 0; i < Nb; i++)
    {
        for(uint8_t j = 0; j < Nb;j++)
        {
            printf("%02x", s[j][i]);
        }
    }
    printf("\n");
}

/*------------------------------------------------------------------------
            PRINT CURRENT STATE IN ARRAY FORM
pre: state in arrary form
post: prints the state in column major order as an array
 -------------------------------------------------------------------------*/
void print_cs_a(uint8_t *s)
{
    for(int8_t i = 0; i < 16; i++)
    {
        printf("%02x", s[i]);
    }
    printf("\n");
}

/*------------------------------------------------------------------------
                            PRINT Round Key
 -------------------------------------------------------------------------*/
void print_rk(uint32_t *rk)
{
    for(int8_t i = 0; i < Nb ; i++)
    {
        printf("%02x", rk[i]);//w3w2w1w0
    }
    printf("\n");
}

/*------------------------------------------------------------------------
                GF Multiplication (09, 0b, 0d, 0e)
1001 = 9
1011 = b
1101 = d
1110 = e

modular multiplication in Gf(2^8) with m(x)=x^8 + x^4+ x^3 + x + 1
using interleaved blakely multiplication.
-------------------------------------------------------------------------*/
uint8_t GFb(uint8_t a, uint8_t b)
{
    uint16_t mx, r, bt;
    
    mx = 0x11b;
    bt = b;
    r = 0x0;
   
    for(int8_t i = 3; i >= 0; i--)
    {
        r = r << 1;
        r = (a & (0x1 << i))? r ^ bt : r;
        r = (r & 0x0100)? r ^ mx : r;
    }
    //printf("%02x %02x %02x\n", a, b, (uint8_t)r);
    return (uint8_t)r;
}


/*------------------------------------------------------------------------
                            GF Multiplication (01, 02, 03)
bx1 = b;
bx2 = b7? (b<<1) ^ mx:(b<<1)
bx3 = bx2 ^ b

modular multiplication in Gf(2^8) with m(x)=x^4+ x^3 + x + 1
since the multiplier is 0x01, 0x02, or 0x03. Multiplication by 0x02 is
implemented as a shift left with conditional XOR is original Msb is 1.
Multiplication by 0x03 is the same but with an additional XOR by b.
-------------------------------------------------------------------------*/
uint8_t GF(uint8_t a, uint8_t b)
{
    uint8_t mx, ap;
    
    mx = 0x1b;
    
    if(a == 0x01) return b; //mul by 1

    ap = b << 1;//mul by 2
    ap = (b & (0x01 << 7))? ap ^ mx: ap;
    
    return (a == 0x02) ? ap : ap ^ b; // mul by 2 or 3
}

/*-------------------------------------------------------------------------
                 Vector Multiplication for InvMixCols
 
 pre: bi row of coeffient matrix and a column sj from the state matrix.
 post: byte entry s'i,j = bi[0](sj[0]) ^ bi[1](sj[1]) ^ bi[2](sj[2]) ^ bi[3](sj[3])
 -------------------------------------------------------------------------*/
uint8_t vectorMultiplicationb(uint8_t *b, uint8_t *s)
{
    return (GFb(b[0],s[0]) ^ GFb(b[1],s[1]) ^ GFb(b[2],s[2]) ^ GFb(b[3],s[3]));
}


/*-------------------------------------------------------------------------
                        Vector Multiplication
pre: ai row of coeffient matrix and a column bj from the state matrix.
 post: byte entry s'i,j = ai[0](bj[0]) ^ ai[1](bj[1]) ^ ai[2](sj[2]) ^ bi[3](sj[3])
 -------------------------------------------------------------------------*/
uint8_t vectorMultiplication(uint8_t a[], uint8_t *b)
{
    return (GF(a[0],b[0]) ^ GF(a[1],b[1]) ^ GF(a[2],b[2]) ^ GF(a[3],b[3]));
}

/*-------------------------------------------------------------------------
                            MixColumns
 
Operates on the state column-wise, each column is treated as a 4-term
polynomials over GF(2^8) and multiplied modulo x^4 + 1 with
fixed polynomial a(x) = {03}x^3   + {01}x^2  + {01}x + {02}
The approach here is matrix multiplication with the coefficient matrix

pre: state matrix s
post: a x s = s`, the update state after the matrix multiplication with
the coefficient matrix a.
-------------------------------------------------------------------------*/
void MixColumns(uint8_t **s)
{
    uint8_t s0[4], s1[4], s2[4], s3[4], a0[4], a1[4], a2[4], a3[4];//cols of s
    //fixed polynomial used for mixed columns_
    /*
    it is this coefficient matrix:
    02 03 01 01
    01 02 02 01
    01 01 02 03
    03 01 01 02
    */
    int8_t a[4][4];
    a[0][0] = 0x02;
    a[0][1] = 0x03;
    a[0][2] = 0x01;
    a[0][3] = 0x01;
    a[1][0] = 0x01;
    a[1][1] = 0x02;
    a[1][2] = 0x03;
    a[1][3] = 0x01;
    a[2][0] = 0x01;
    a[2][1] = 0x01;
    a[2][2] = 0x02;
    a[2][3] = 0x03;
    a[3][0] = 0x03;
    a[3][1] = 0x01;
    a[3][2] = 0x01;
    a[3][3] = 0x02;

    //must be done in this manner... all new products f(original values of s and s):
    for(int8_t c = 0; c < 4; c = c + 1)
    {
        s0[c] = s[c][0];
        s1[c] = s[c][1];
        s2[c] = s[c][2];
        s3[c] = s[c][3];
        a0[c] = a[0][c];
        a1[c] = a[1][c];
        a2[c] = a[2][c];
        a3[c] = a[3][c];
    }
    //indivual + and MUL in Gf(2^8)
    //for corresponding rows and cols in a and state to get each new byte...
    s[0][0] = vectorMultiplication(a0,s0);
    s[1][0] = vectorMultiplication(a1,s0);
    s[2][0] = vectorMultiplication(a2,s0);
    s[3][0] = vectorMultiplication(a3,s0);
    s[0][1] = vectorMultiplication(a0,s1);
    s[1][1] = vectorMultiplication(a1,s1);
    s[2][1] = vectorMultiplication(a2,s1);
    s[3][1] = vectorMultiplication(a3,s1);
    s[0][2] = vectorMultiplication(a0,s2);
    s[1][2] = vectorMultiplication(a1,s2);
    s[2][2] = vectorMultiplication(a2,s2);
    s[3][2] = vectorMultiplication(a3,s2);
    s[0][3] = vectorMultiplication(a0,s3);
    s[1][3] = vectorMultiplication(a1,s3);
    s[2][3] = vectorMultiplication(a2,s3);
    s[3][3] = vectorMultiplication(a3,s3);
}

/*-------------------------------------------------------------------------
                            InvMixColumns
 
  operates on the state column-wise, each column is treated as a 4-term
  polynomials over GF(2^8) and multiplied modulo x^4 + 1 with
  fixed polynomial a(x) = {03}x^3   + {01}x^2  + {01}x + {02}
  The approach here is matrix multiplication with the coefficient matrix

pre: state matrix s
post: b x s = s`, the update state after the matrix multiplication with
the coefficient matrix b. We know that... a x b = identity matrix...
we get back the original entry sij, or state byte.
-------------------------------------------------------------------------*/
void InvMixColumns(uint8_t **s)
{
    uint8_t s0[4], s1[4], s2[4], s3[4], b0[4], b1[4], b2[4], b3[4];//cols of s
    //fixed polynomial used for mixed columns_
    /*
    it is this coefficient matrix:
    0e 0b 0d 09
    09 0e 0b 0d
    0d 09 0e 0b
    0b 0d 09 0e
    */
    int8_t b[4][4];
    b[0][0] = 0x0e;
    b[0][1] = 0x0b;
    b[0][2] = 0x0d;
    b[0][3] = 0x09;
    b[1][0] = 0x09;
    b[1][1] = 0x0e;
    b[1][2] = 0x0b;
    b[1][3] = 0x0d;
    b[2][0] = 0x0d;
    b[2][1] = 0x09;
    b[2][2] = 0x0e;
    b[2][3] = 0x0b;
    b[3][0] = 0x0b;
    b[3][1] = 0x0d;
    b[3][2] = 0x09;
    b[3][3] = 0x0e;

    //must be done in this manner... all new products f(original values of s and s):
    for(int8_t c = 0; c < 4; c = c + 1)
    {
        s0[c] = s[c][0];
        s1[c] = s[c][1];
        s2[c] = s[c][2];
        s3[c] = s[c][3];
        b0[c] = b[0][c];
        b1[c] = b[1][c];
        b2[c] = b[2][c];
        b3[c] = b[3][c];
    }
    
    //indivual + and MUL in Gf(2^8)
    //for corresponding rows and cols in a and state to get each new byte...
    s[0][0] = vectorMultiplicationb(b0,s0);
    //printf("s'00 = %02x\n",s[0][0]);
    s[1][0] = vectorMultiplicationb(b1,s0);
    s[2][0] = vectorMultiplicationb(b2,s0);
    s[3][0] = vectorMultiplicationb(b3,s0);
    s[0][1] = vectorMultiplicationb(b0,s1);
    s[1][1] = vectorMultiplicationb(b1,s1);
    s[2][1] = vectorMultiplicationb(b2,s1);
    s[3][1] = vectorMultiplicationb(b3,s1);
    s[0][2] = vectorMultiplicationb(b0,s2);
    s[1][2] = vectorMultiplicationb(b1,s2);
    s[2][2] = vectorMultiplicationb(b2,s2);
    s[3][2] = vectorMultiplicationb(b3,s2);
    s[0][3] = vectorMultiplicationb(b0,s3);
    s[1][3] = vectorMultiplicationb(b1,s3);
    s[2][3] = vectorMultiplicationb(b2,s3);
    s[3][3] = vectorMultiplicationb(b3,s3);
}


/*-------------------------------------------------------------------------
                             ShiftRows
 
performs cyclic shift left on rows 1, 2, 3 by 1, 2, & 3 respectively.

pre: state matrix s
post: updates s post the shifts.
-------------------------------------------------------------------------*/
void ShiftRows(uint8_t **s)
{
    uint8_t temp;
    temp = s[1][0]; //s10,s11,s12,s13 -> s11,s12,s13,s10
    s[1][0] = s[1][1]; s[1][1] = s[1][2]; s[1][2] = s[1][3]; s[1][3] = temp;
    temp = s[2][0]; //(s20,s21,)s22,s23 -> s22,s23,s20,s21
    s[2][0] = s[2][2]; s[2][2] = temp;
    temp = s[2][1];
    s[2][1] = s[2][3]; s[2][3] = temp;
    temp = s[3][3]; //(s30,s31,s32,)s33 -> s33,s30,s31,s32
    s[3][3] = s[3][2]; s[3][2] = s[3][1]; s[3][1] = s[3][0]; s[3][0] = temp;
}

/*-------------------------------------------------------------------------
                             ShiftRows:
 
performs cyclic right shift on rows 1, 2, 3 by 1, 2, & 3 respectively.
pre: state matrix s
post: updates s post the shifts.
-------------------------------------------------------------------------*/
void InvShiftRows(uint8_t **s)
{
    uint8_t temp;
    
    temp = s[1][3]; //s10,s11,s12,s13 -> (s13)s10,s11,s12
    s[1][3] = s[1][2]; s[1][2] = s[1][1]; s[1][1] = s[1][0]; s[1][0] = temp;
    temp = s[2][0]; //s20,s21,s22,s23 -> (s22,s23,)s20,s21
    s[2][0] = s[2][2]; s[2][2] = temp;
    temp = s[2][1];
    s[2][1] = s[2][3]; s[2][3] = temp;
    temp = s[3][0]; //s30,s31,s32,s33 -> s30,s31,s32,(s33)
    s[3][0] = s[3][1]; s[3][1] = s[3][2]; s[3][2] = s[3][3]; s[3][3] = temp;
}

/*-------------------------------------------------------------------------
                SubByte applies the S-box to input byte
 
 pre: si,j byte entry of state, lower 4 bits = column index c, upper 4bits = row index r
 post: s`i,j the table lookup value for sbox[r,c].
-------------------------------------------------------------------------*/
uint8_t SubByte(uint8_t s)
{
   uint8_t r, c, sbox[16][16];//byte lookup table
   
    sbox[0][0] = 0x63;  sbox[0][1] = 0x7c;  sbox[0][2] = 0x77;  sbox[0][3] = 0x7b;
    sbox[0][4] = 0xf2;  sbox[0][5] = 0x6b;  sbox[0][6] = 0x6f;  sbox[0][7] = 0xc5;
    sbox[0][8] = 0x30;  sbox[0][9] = 0x1;  sbox[0][10] = 0x67;  sbox[0][11] = 0x2b;
    sbox[0][12] = 0xfe;  sbox[0][13] = 0xd7;  sbox[0][14] = 0xab;  sbox[0][15] = 0x76;
    sbox[1][0] = 0xca;  sbox[1][1] = 0x82;  sbox[1][2] = 0xc9;  sbox[1][3] = 0x7d;
    sbox[1][4] = 0xfa;  sbox[1][5] = 0x59;  sbox[1][6] = 0x47;  sbox[1][7] = 0xf0;
    sbox[1][8] = 0xad;  sbox[1][9] = 0xd4;  sbox[1][10] = 0xa2;  sbox[1][11] = 0xaf;
    sbox[1][12] = 0x9c;  sbox[1][13] = 0xa4;  sbox[1][14] = 0x72;  sbox[1][15] = 0xc0;
    sbox[2][0] = 0xb7;  sbox[2][1] = 0xfd;  sbox[2][2] = 0x93;  sbox[2][3] = 0x26;
    sbox[2][4] = 0x36;  sbox[2][5] = 0x3f;  sbox[2][6] = 0xf7;  sbox[2][7] = 0xcc;
    sbox[2][8] = 0x34;  sbox[2][9] = 0xa5;  sbox[2][10] = 0xe5;  sbox[2][11] = 0xf1;
    sbox[2][12] = 0x71;  sbox[2][13] = 0xd8;  sbox[2][14] = 0x31;  sbox[2][15] = 0x15;
    sbox[3][0] = 0x4;  sbox[3][1] = 0xc7;  sbox[3][2] = 0x23;  sbox[3][3] = 0xc3;
    sbox[3][4] = 0x18;  sbox[3][5] = 0x96;  sbox[3][6] = 0x5;  sbox[3][7] = 0x9a;
    sbox[3][8] = 0x7;  sbox[3][9] = 0x12;  sbox[3][10] = 0x80;  sbox[3][11] = 0xe2;
    sbox[3][12] = 0xeb;  sbox[3][13] = 0x27;  sbox[3][14] = 0xb2;  sbox[3][15] = 0x75;
    sbox[4][0] = 0x9;  sbox[4][1] = 0x83;  sbox[4][2] = 0x2c;  sbox[4][3] = 0x1a;
    sbox[4][4] = 0x1b;  sbox[4][5] = 0x6e;  sbox[4][6] = 0x5a;  sbox[4][7] = 0xa0;
    sbox[4][8] = 0x52;  sbox[4][9] = 0x3b;  sbox[4][10] = 0xd6;  sbox[4][11] = 0xb3;
    sbox[4][12] = 0x29;  sbox[4][13] = 0xe3;  sbox[4][14] = 0x2f;  sbox[4][15] = 0x84;
    sbox[5][0] = 0x53;  sbox[5][1] = 0xd1;  sbox[5][2] = 0x0;  sbox[5][3] = 0xed;
    sbox[5][4] = 0x20;  sbox[5][5] = 0xfc;  sbox[5][6] = 0xb1;  sbox[5][7] = 0x5b;
    sbox[5][8] = 0x6a;  sbox[5][9] = 0xcb;  sbox[5][10] = 0xbe;  sbox[5][11] = 0x39;
    sbox[5][12] = 0x4a;  sbox[5][13] = 0x4c;  sbox[5][14] = 0x58;  sbox[5][15] = 0xcf;
    sbox[6][0] = 0xd0;  sbox[6][1] = 0xef;  sbox[6][2] = 0xaa;  sbox[6][3] = 0xfb;
    sbox[6][4] = 0x43;  sbox[6][5] = 0x4d;  sbox[6][6] = 0x33;  sbox[6][7] = 0x85;
    sbox[6][8] = 0x45;  sbox[6][9] = 0xf9;  sbox[6][10] = 0x2;  sbox[6][11] = 0x7f;
    sbox[6][12] = 0x50;  sbox[6][13] = 0x3c;  sbox[6][14] = 0x9f;  sbox[6][15] = 0xa8;
    sbox[7][0] = 0x51;  sbox[7][1] = 0xa3;  sbox[7][2] = 0x40;  sbox[7][3] = 0x8f;
    sbox[7][4] = 0x92;  sbox[7][5] = 0x9d;  sbox[7][6] = 0x38;  sbox[7][7] = 0xf5;
    sbox[7][8] = 0xbc;  sbox[7][9] = 0xb6;  sbox[7][10] = 0xda;  sbox[7][11] = 0x21;
    sbox[7][12] = 0x10;  sbox[7][13] = 0xff;  sbox[7][14] = 0xf3;  sbox[7][15] = 0xd2;
    sbox[8][0] = 0xcd;  sbox[8][1] = 0xc;  sbox[8][2] = 0x13;  sbox[8][3] = 0xec;
    sbox[8][4] = 0x5f;  sbox[8][5] = 0x97;  sbox[8][6] = 0x44;  sbox[8][7] = 0x17;
    sbox[8][8] = 0xc4;  sbox[8][9] = 0xa7;  sbox[8][10] = 0x7e;  sbox[8][11] = 0x3d;
    sbox[8][12] = 0x64;  sbox[8][13] = 0x5d;  sbox[8][14] = 0x19;  sbox[8][15] = 0x73;
    sbox[9][0] = 0x60;  sbox[9][1] = 0x81;  sbox[9][2] = 0x4f;  sbox[9][3] = 0xdc;
    sbox[9][4] = 0x22;  sbox[9][5] = 0x2a;  sbox[9][6] = 0x90;  sbox[9][7] = 0x88;
    sbox[9][8] = 0x46;  sbox[9][9] = 0xee;  sbox[9][10] = 0xb8;  sbox[9][11] = 0x14;
    sbox[9][12] = 0xde;  sbox[9][13] = 0x5e;  sbox[9][14] = 0xb;  sbox[9][15] = 0xdb;
    sbox[10][0] = 0xe0;  sbox[10][1] = 0x32;  sbox[10][2] = 0x3a;  sbox[10][3] = 0xa;
    sbox[10][4] = 0x49;  sbox[10][5] = 0x6;  sbox[10][6] = 0x24;  sbox[10][7] = 0x5c;
    sbox[10][8] = 0xc2;  sbox[10][9] = 0xd3;  sbox[10][10] = 0xac;  sbox[10][11] = 0x62;
    sbox[10][12] = 0x91;  sbox[10][13] = 0x95;  sbox[10][14] = 0xe4;  sbox[10][15] = 0x79;
    sbox[11][0] = 0xe7;  sbox[11][1] = 0xc8;  sbox[11][2] = 0x37;  sbox[11][3] = 0x6d;
    sbox[11][4] = 0x8d;  sbox[11][5] = 0xd5;  sbox[11][6] = 0x4e;  sbox[11][7] = 0xa9;
    sbox[11][8] = 0x6c;  sbox[11][9] = 0x56;  sbox[11][10] = 0xf4;  sbox[11][11] = 0xea;
    sbox[11][12] = 0x65;  sbox[11][13] = 0x7a;  sbox[11][14] = 0xae;  sbox[11][15] = 0x8;
    sbox[12][0] = 0xba;  sbox[12][1] = 0x78;  sbox[12][2] = 0x25;  sbox[12][3] = 0x2e;
    sbox[12][4] = 0x1c;  sbox[12][5] = 0xa6;  sbox[12][6] = 0xb4;  sbox[12][7] = 0xc6;
    sbox[12][8] = 0xe8;  sbox[12][9] = 0xdd;  sbox[12][10] = 0x74;  sbox[12][11] = 0x1f;
    sbox[12][12] = 0x4b;  sbox[12][13] = 0xbd;  sbox[12][14] = 0x8b;  sbox[12][15] = 0x8a;
    sbox[13][0] = 0x70;  sbox[13][1] = 0x3e;  sbox[13][2] = 0xb5;  sbox[13][3] = 0x66;
    sbox[13][4] = 0x48;  sbox[13][5] = 0x3;  sbox[13][6] = 0xf6;  sbox[13][7] = 0xe;
    sbox[13][8] = 0x61;  sbox[13][9] = 0x35;  sbox[13][10] = 0x57;  sbox[13][11] = 0xb9;
    sbox[13][12] = 0x86;  sbox[13][13] = 0xc1;  sbox[13][14] = 0x1d;  sbox[13][15] = 0x9e;
    sbox[14][0] = 0xe1;  sbox[14][1] = 0xf8;  sbox[14][2] = 0x98;  sbox[14][3] = 0x11;
    sbox[14][4] = 0x69;  sbox[14][5] = 0xd9;  sbox[14][6] = 0x8e;  sbox[14][7] = 0x94;
    sbox[14][8] = 0x9b;  sbox[14][9] = 0x1e;  sbox[14][10] = 0x87;  sbox[14][11] = 0xe9;
    sbox[14][12] = 0xce;  sbox[14][13] = 0x55;  sbox[14][14] = 0x28;  sbox[14][15] = 0xdf;
    sbox[15][0] = 0x8c;  sbox[15][1] = 0xa1;  sbox[15][2] = 0x89;  sbox[15][3] = 0xd;
    sbox[15][4] = 0xbf;  sbox[15][5] = 0xe6;  sbox[15][6] = 0x42;  sbox[15][7] = 0x68;
    sbox[15][8] = 0x41;  sbox[15][9] = 0x99;  sbox[15][10] = 0x2d;  sbox[15][11] = 0xf;
    sbox[15][12] = 0xb0;  sbox[15][13] = 0x54;  sbox[15][14] = 0xbb;  sbox[15][15] = 0x16;

   c = 0x0f & s;
   r = (0xf0 & s) >> 4;
   
   return sbox[r][c];
}

/*-------------------------------------------------------------------------
        InvSubByte applies the Inverse S-box to a input byte
 
 pre:  si,j byte entry of state, lower 4 bits = column index c, upper 4bits = row index r
 post: s`i,j the table lookup value for sbox[r,c].
-------------------------------------------------------------------------*/
uint8_t InvSubByte(uint8_t s)
{
    uint8_t r, c;
    
    uint8_t inv_sbox[16][16] = {//byte lookup table
    {0x52,  0x9,    0x6a,   0xd5,   0x30,   0x36,   0xa5,   0x38,   0xbf,   0x40,   0xa3,   0x9e,   0x81,   0xf3,   0xd7,   0xfb},
    {0x7c,  0xe3,   0x39,   0x82,   0x9b,   0x2f,   0xff,   0x87,   0x34,   0x8e,   0x43,   0x44 ,  0xc4,   0xde ,  0xe9,   0xcb},
    {0x54,  0x7b,   0x94,   0x32,   0xa6,   0xc2,   0x23,   0x3d,   0xee,   0x4c,   0x95,   0x0b,   0x42,   0xfa,   0xc3,   0x4e},
    {0x8,   0x2e,   0xa1,   0x66,   0x28,   0xd9,   0x24,   0xb2,   0x76,   0x5b,   0xa2,   0x49,   0x6d,   0x8b,   0xd1,   0x25},
    {0x72,  0xf8,   0xf6,   0x64,   0x86,   0x68,   0x98,   0x16,   0xd4,   0xa4,   0x5c,   0xcc,   0x5d,   0x65,   0xb6,   0x92},
    {0x6c,  0x70,   0x48,   0x50,   0xfd,   0xed,   0xb9,   0xda,   0x5e,   0x15,   0x46,   0x57,   0xa7,   0x8d,   0x9d,   0x84},
    {0x90,  0xd8,   0xab,   0x0,    0x8c,   0xbc,   0xd3,   0x0a,   0xf7,   0xe4,   0x58,   0x5,    0xb8,   0xb3,   0x45,   0x6},
    {0xd0,  0x2c,   0x1e,   0x8f,   0xca,   0x3f,   0x0f,   0x2,    0xc1,   0xaf,   0xbd,   0x3,    0x1,    0x13,   0x8a,   0x6b},
    {0x3a,  0x91,   0x11,   0x41,   0x4f,   0x67,   0xdc,   0xea,   0x97,   0xf2,   0xcf,   0xce,   0xf0,   0xb4,   0xe6,   0x73},
    {0x96,  0xac,   0x74,   0x22,   0xe7,   0xad,   0x35,   0x85,   0xe2,   0xf9,   0x37,   0xe8,   0x1c,   0x75,   0xdf,   0x6e},
    {0x47,  0xf1,   0x1a,   0x71,   0x1d,   0x29,   0xc5,   0x89,   0x6f,   0xb7,   0x62,   0x0e,   0xaa,   0x18,   0xbe,   0x1b},
    {0xfc,  0x56,   0x3e,   0x4b,   0xc6,   0xd2,   0x79,   0x20,   0x9a,   0xdb,   0xc0,   0xfe,   0x78,   0xcd,   0x5a,   0xf4},
    {0x1f,  0xdd,   0xa8,   0x33,   0x88,   0x7,    0xc7,   0x31,   0xb1,   0x12,   0x10,   0x59,   0x27,   0x80,   0xec,   0x5f},
    {0x60,  0x51,   0x7f,   0xa9,   0x19,   0xb5,   0x4a,   0x0d,   0x2d,   0xe5,   0x7a,   0x9f,   0x93,   0xc9,   0x9c,   0xef},
    {0xa0,  0xe0,   0x3b,   0x4d,   0xae,   0x2a,   0xf5,   0xb0,   0xc8,   0xeb,   0xbb,   0x3c,   0x83,   0x53,   0x99,   0x61},
    {0x17,  0x2b,   0x4,    0x7e,   0xba,   0x77,   0xd6,   0x26,   0xe1,   0x69 ,  0x14 ,  0x63,   0x55,   0x21,   0x0c,   0x7d}
    };
    
   c = 0x0f & s;
   r = (0xf0 & s) >> 4;
   
   return inv_sbox[r][c];

}

/*-------------------------------------------------------------------------
                Subbytes applies the S-box to current state
-------------------------------------------------------------------------*/
void SubBytes(uint8_t **s)
{
    s[0][0] = SubByte(s[0][0]);
    s[0][1] = SubByte(s[0][1]);
    s[0][2] = SubByte(s[0][2]);
    s[0][3] = SubByte(s[0][3]);
    s[1][0] = SubByte(s[1][0]);
    s[1][1] = SubByte(s[1][1]);
    s[1][2] = SubByte(s[1][2]);
    s[1][3] = SubByte(s[1][3]);
    s[2][0] = SubByte(s[2][0]);
    s[2][1] = SubByte(s[2][1]);
    s[2][2] = SubByte(s[2][2]);
    s[2][3] = SubByte(s[2][3]);
    s[3][0] = SubByte(s[3][0]);
    s[3][1] = SubByte(s[3][1]);
    s[3][2] = SubByte(s[3][2]);
    s[3][3] = SubByte(s[3][3]);
}


/*-------------------------------------------------------------------------
                Subbytes applies Inv S-box to current state
-------------------------------------------------------------------------*/
void InvSubBytes(uint8_t **s)
{
    s[0][0] = InvSubByte(s[0][0]);
    s[0][1] = InvSubByte(s[0][1]);
    s[0][2] = InvSubByte(s[0][2]);
    s[0][3] = InvSubByte(s[0][3]);
    s[1][0] = InvSubByte(s[1][0]);
    s[1][1] = InvSubByte(s[1][1]);
    s[1][2] = InvSubByte(s[1][2]);
    s[1][3] = InvSubByte(s[1][3]);
    s[2][0] = InvSubByte(s[2][0]);
    s[2][1] = InvSubByte(s[2][1]);
    s[2][2] = InvSubByte(s[2][2]);
    s[2][3] = InvSubByte(s[2][3]);
    s[3][0] = InvSubByte(s[3][0]);
    s[3][1] = InvSubByte(s[3][1]);
    s[3][2] = InvSubByte(s[3][2]);
    s[3][3] = InvSubByte(s[3][3]);
}


/*-------------------------------------------------------------------------
            SubWord applies the S-box to a four-byte input
-------------------------------------------------------------------------*/
uint32_t SubWord(uint32_t s)
{
    uint32_t sp, mask;
    uint8_t byte0, byte1, byte2, byte3;
    
    byte0 = 0x000000ff & s; //get truncated so we are good
    byte1 = (0x0000ff00 & s) >> 8;
    byte2 = (0x00ff0000 & s) >> 16;
    byte3 = (0xff000000 & s) >> 24;
    
    sp = 0x0;
    sp |= SubByte(byte0);
    mask = SubByte(byte1);
    sp |= mask << 8;
    mask = SubByte(byte2);
    sp |= mask << 16;
    mask = SubByte(byte3);
    sp |= mask << 24;
    
    return sp;
}

/*-------------------------------------------------------------------------
                Rotate Word is a circular left shift
-------------------------------------------------------------------------*/
uint32_t RotateWord(uint32_t s)
{
    return ((s << 8) | (s >> 24));
}

/*-------------------------------------------------------------------------
                            Key Expansion
-------------------------------------------------------------------------*/
uint32_t *KeyExpansion(uint8_t *key)
{
    uint32_t mask, temp, *w;
    uint8_t wWidth;

    
    wWidth = Nb * (Nr + 1); //bytes
    w = calloc(wWidth, sizeof(uint32_t));
    //copy key into first four words of expanded key
    for(int8_t i = 0; i < Nk; i++)
    {
        w[i] = key[4*i + 3];
        mask = key[4*i + 2];
        w[i] |= (mask << 8);
        mask = key[4*i + 1];
        w[i] |= (mask << 16);
        mask = key[4*i];
        w[i] |= (mask << 24);
        //printf("%02x\n", w[i]);
    }
    
    //derive the rest of the keys
    for(int8_t i = Nk; i < wWidth; i++)
    {
        temp = w[i-1];
        if(i % Nk == 0)
        {
            //printf("%02x\n",RotateWord(temp));
            //printf("%02x\n",SubWord(RotateWord(temp)));
            temp = SubWord(RotateWord(temp)) ^ Rcon[(i / Nk) - 1];
            //printf("%02x\n",temp);
        }
        if(Nk > 6 && i % Nk == 4)
        {
            temp = SubWord(temp);
        }
        w[i] = w[i-Nk] ^ temp;
        //printf("i=%d  w = %02x\n",i, w[i]);
    }
    return w;
}

/*-------------------------------------------------------------------------
                    Key Schedule  for  Inverse Cipher
 pre: uint32_t *w, array of words of depth (Nr+1)*4 s.t. the ith round_key
      is {w[(Nr+1)*4-1],w[(Nr+1)*4-2],w[(Nr+1)*4-3],w[(Nr+1)*4-4]} for i=43 to 0
 post: uint32_t **dw, array of round keys. depth (Nr+1) and width 4*(uint32_t)
-------------------------------------------------------------------------*/
uint32_t **BackwardKeySchedule(uint32_t *w)
{
    uint32_t **dw;//array of round keys
    
    dw = (uint32_t**)calloc(Nr+1, sizeof(uint32_t*));
    for(u_int8_t i=0, j= (Nr+1)*Nb; i <= Nr; i++, j -= 4)
    {
            dw[i] = (uint32_t*)calloc(Nb, sizeof(uint32_t));
            dw[i][3] = w[j-1]; dw[i][2] = w[j-2]; dw[i][1] = w[j-3]; dw[i][0] = w[j-4];
        
    }
    return dw;
}

/*-------------------------------------------------------------------------
                    Key Schedule  for Cipher
 pre: uint32_t *w, array of words of depth (Nr+1)*4 s.t. ith round_key
      is {w[4*i+3],w[4*i+2],w[4*i+1],w[4*i]} for i=0 to 43
 post: uint32_t **dw, array of round keys. depth (Nr+1) and width 4*(uint32_t)
-------------------------------------------------------------------------*/
uint32_t **ForwardKeySchedule(uint32_t *w)
{
    uint32_t **dw;//array of round keys
    
    dw = (uint32_t**)calloc(Nr+1, sizeof(uint32_t*));
    for(u_int8_t i=0; i <= Nr; i++)
    {
            dw[i] = (uint32_t*)calloc(Nb, sizeof(uint32_t));
            dw[i][3] = w[4*i+3]; dw[i][2] = w[4*i+2]; dw[i][1] = w[4*i+1]; dw[i][0] = w[4*i];
    }
    return dw;
}

/*-------------------------------------------------------------------------
                            AddRoundKey
-------------------------------------------------------------------------*/
void AddRoundKey(uint8_t **s, uint32_t *w)
{
    //xor with the w_i column wise
    uint8_t temp;
    for(uint8_t c = 0; c < Nb; c = c + 1)
    {
        temp = (0xff000000 & w[c]) >> 24;//gets truncated to fit the uint
        s[0][c] ^= temp;
        temp = (0x00ff0000 & w[c]) >> 16;
        s[1][c] ^= temp;
        temp = (0x0000ff00 & w[c]) >> 8;
        s[2][c] ^= temp;
        temp = (0x000000ff & w[c]);
        s[3][c] ^= temp;
    }
}

/*-------------------------------------------------------------------------
                           Initialize state
-------------------------------------------------------------------------*/
uint8_t **initialize_state(uint8_t *plaintext)
{
    uint8_t **state;
    //initialize the state matrix in column-major order...
    state = (uint8_t**)malloc(4*sizeof(uint8_t*));
    for(uint8_t r = 0 ; r < 4; r++)
    {
        state[r] = (uint8_t*)malloc(4*sizeof(uint8_t));
        for(uint8_t c = 0; c < 4; c++)
        {
            state[r][c] = plaintext[r + 4*c];
        }
    }
    return state;
}

/*-------------------------------------------------------------------------
                        state to array format
-------------------------------------------------------------------------*/
uint8_t *state_to_array(uint8_t **state)
{
    uint8_t *ary;
    //copy in CT format and return by address
    //initialize the state matrix in column-major order...
    ary = (uint8_t*)malloc(sizeof(uint8_t)*16);
    for(uint8_t r = 0 ; r < 4; r++)
    {
        for(uint8_t c = 0; c < 4; c++)
        {
           ary[4*r + c] = state[c][r];
        }
    }
    return ary;
}
/*-------------------------------------------------------------------------
                            Round Function f
-------------------------------------------------------------------------*/
void f(uint8_t **state, uint32_t *round_key)
{
    //SUBYTES
    SubBytes(state);
    //SHIFROWS
    ShiftRows(state);
    //MIXCOLS
    MixColumns(state);
    //ADDROUND KEY
    AddRoundKey(state, round_key);
}

/*-------------------------------------------------------------------------
                        Inverse Round Function
-------------------------------------------------------------------------*/
void f_1(uint8_t **state, uint32_t *round_key)
{
    //Inverse SHIFTROWS
    InvShiftRows(state);
    //Inverse SUBYTES
    InvSubBytes(state);
    //ADDROUND KEY
    AddRoundKey(state, round_key);
    //INVMIXCOLS
    InvMixColumns(state);
}

/*-------------------------------------------------------------------------
                        Set Nk and Nr Parameters
 
 Default is set for AES-128.
 pre: type (2) for 192 and (3) for 256
-------------------------------------------------------------------------*/
void set_parameters(uint8_t type)
{
    if(type == 1)//192
    {
        Nk = 6;
        Nr = 12;
    }
    if(type == 2)//1256
    {
        Nk = 8;
        Nr = 14;
    }
}

/*-------------------------------------------------------------------------
                        AES ENCRYPTION
-------------------------------------------------------------------------*/
uint8_t *aes_encrypt(uint8_t *plaintext, uint8_t *key, uint8_t type)
{
    uint32_t *w, **dw; //round keys array of 44 entries at 32-bits each
    uint8_t *ciphertext;
    uint8_t **state;
    
    if(type != 0)set_parameters(type);
    //Key Expansion & Schedule
    w = KeyExpansion(key);
    dw = ForwardKeySchedule(w);
    free(w);
    
    //Intialize State
    state = initialize_state(plaintext);
    
    //round 0
    AddRoundKey(state, dw[0]);
    
    //Iterate the round function for round=1 to Nr-1
    for(uint8_t i = 1; i < Nr; i++)
        f(state, dw[i]);
    
    //Last round Nr
    //SUBYTES
    SubBytes(state);
    //SHIFROWS
    ShiftRows(state);
    //ADDROUND KEY
    AddRoundKey(state, dw[Nr]);
    
    free(dw);
    free(state);
    ciphertext = state_to_array(state);
    
    return ciphertext;
}

/*-------------------------------------------------------------------------
                            AES DECRYPTION
 This form was selected over the equivalent inverse cipher since that
 involves changing the round key
 
-------------------------------------------------------------------------*/
uint8_t *aes_decrypt(uint8_t *ciphertext, uint8_t *key, uint8_t type)
{
    uint32_t *w, **dw; //round keys array of 44 entries at 32-bits each
    uint8_t **state, *plaintext;
    
    if(type != 0)set_parameters(type);
    //Key Expansion & Schedule
    w = KeyExpansion(key);
    dw = BackwardKeySchedule(w);
    free(w);

    //Intialize State
    state = initialize_state(ciphertext);
    //round 0
    AddRoundKey(state, dw[0]);
    
    //Iterate the inverse round function for round=1 to Nr-1
    for(uint8_t i = 1; i < Nr; i++)
        f_1(state, dw[i]);

    //Last round Nr
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, dw[Nr]);
    
    plaintext = state_to_array(state);
    free(dw);
    free(state);
    
    return plaintext;
}

#endif /* aes_128_h */

