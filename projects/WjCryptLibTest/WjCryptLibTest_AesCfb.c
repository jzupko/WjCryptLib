////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  WjCryptLibTest_AesCfb
//
//  Tests the cryptography functions against known test vectors to verify algorithms are correct.
//  Tests the following:
//     AES CFB
//
//  This is free and unencumbered software released into the public domain - January 2020 Joseph A. Zupko <jazupko@jazupko.com>
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  IMPORTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "WjCryptLib_AesCfb.h"
#include "WjCryptLib_Sha1.h"
#include "WjCryptLib_Rc4.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  MACROS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define MIN( x, y ) ( ((x)<(y))?(x):(y) )

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  TYPES
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define MAX_PLAINTEXT_SIZE      100

typedef struct
{
    char*           KeyHex;
    char*           IvHex;
    char*           CipherTextHex;
} TestVector;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  GLOBALS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// These test vectors were created using openssl. Using the following commands:
// (Note: As CFB is not a stream cipher, the input is created using an RC4 stream generated from a key of 0)
// (Also note: openssl outputs an additional block of data due to some padding. We ignore this)
//   > dd if=/dev/zero iflag=count_bytes count=64 status=none | openssl enc -rc4 -K 0 | openssl enc -aes-128-cfb -K 00000000000000000000000000000000 -iv 00000000000000000000000000000000 | head -c 64 | xxd -p -c 64
//   > dd if=/dev/zero iflag=count_bytes count=64 status=none | openssl enc -rc4 -K 0 | openssl enc -aes-128-cfb -K 0102030405060708a1a2a3a4a5a6a7a8 -iv 00000000000000000000000000000000 | head -c 64 | xxd -p -c 64
//   > dd if=/dev/zero iflag=count_bytes count=64 status=none | openssl enc -rc4 -K 0 | openssl enc -aes-128-cfb -K 00000000000000000000000000000000 -iv b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8 | head -c 64 | xxd -p -c 64
//   > dd if=/dev/zero iflag=count_bytes count=64 status=none | openssl enc -rc4 -K 0 | openssl enc -aes-128-cfb -K 0102030405060708a1a2a3a4a5a6a7a8 -iv b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8 | head -c 64 | xxd -p -c 64
//   > dd if=/dev/zero iflag=count_bytes count=64 status=none | openssl enc -rc4 -K 0 | openssl enc -aes-192-cfb -K 0102030405060708a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8 -iv c1c2c3c4c5c6c7c8d1d2d3d4d5d6d7d8 | head -c 64 | xxd -p -c 64
//   > dd if=/dev/zero iflag=count_bytes count=64 status=none | openssl enc -rc4 -K 0 | openssl enc -aes-256-cfb -K 0102030405060708a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8 -iv d1d2d3d4d5d6d7d8e1e2e3e4e5e6e7e8 | head -c 64 | xxd -p -c 64
static TestVector gTestVectors [] =
{
    {
        "00000000000000000000000000000000",
        "00000000000000000000000000000000",
        "b8f1c2954cbd7101024ae43e9d5ab9433a2e27b381b25b8a63326bd732dad46168ee3e2ab11306132ecb2ce60bbb35fa60b78ea26629a8994ad7f9715b91c16e"
    },
    {
        "0102030405060708a1a2a3a4a5a6a7a8",
        "00000000000000000000000000000000",
        "13abb562cf9d4861a2d7500ae43ec11cd9e285d7af33d1cf4a36b258046a381d2795d5a0f572bde98fe87deabc10b83a7e9620c8a6362c1f78b2909e100b0da6"
    },
    {
        "00000000000000000000000000000000",
        "b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8",
        "4de4c422d7eb0977ca1e035e5100096d5db9d2a4da1572a89cfb75b89c1f0200e367454292f8ed2367aca20260198736ca604fb9976677f02bd66ca6845709c0"
    },
    {
        "0102030405060708a1a2a3a4a5a6a7a8",
        "b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8",
        "8b0639857baa2321d97d2e9170a2c867daeaa21f1766e64e5a8690b1d99aa7e55d384391bc7142599b761cf5b56be7e3a992bfa3608c8686f479c2f2c3dae94a"
    },
    {
        "0102030405060708a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8",
        "c1c2c3c4c5c6c7c8d1d2d3d4d5d6d7d8",
        "370a04b88ce6877eb58473e3aa282c2d28c144ad0cc1448eee7fcdd563ea8a638b7c7c25aa6cb3cee649131e4855a633b3a44c95c90f31f8199f0d5f6576054e"
    },
    {
        "0102030405060708a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8c1c2c3c4c5c6c7c8",
        "d1d2d3d4d5d6d7d8e1e2e3e4e5e6e7e8",
        "d8b12b4180e320cd0058b3f0263417ffd9dc611d7ee9fa1041051c342099c33dcffcf8afd56cde097052f729a8d05ad94ac35de06346ebb09031ae40b61d837f"
    },
};

#define NUM_TEST_VECTORS ( sizeof(gTestVectors) / sizeof(gTestVectors[0]) )
#define TEST_VECTOR_OUTPUT_SIZE     48

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  INTERNAL FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  HexToBytes
//
//  Reads a string as hex and places it in Data. This function will output as many bytes as represented in the input
//  string, it will not check the output buffer length. On return *pDataSize will be number of bytes read.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
void
    HexToBytes
    (
        char const*         HexString,              // [in]
        uint8_t*            Data,                   // [out]
        uint32_t*           pDataSize               // [out optional]
    )
{
    uint32_t        i;
    char            holdingBuffer [3] = {0};
    unsigned        hexToNumber;
    uint32_t        outputIndex = 0;

    for( i=0; i<strlen(HexString)/2; i++ )
    {
        holdingBuffer[0] = HexString[i*2 + 0];
        holdingBuffer[1] = HexString[i*2 + 1];
        sscanf( holdingBuffer, "%x", &hexToNumber );
        Data[i] = (uint8_t) hexToNumber;
        outputIndex += 1;
    }

    if( NULL != pDataSize )
    {
        *pDataSize = outputIndex;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  TestVectors
//
//  Tests AES CFB against fixed test vectors
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
bool
    TestVectors
    (
        void
    )
{
    uint32_t        vectorIndex;
    uint8_t         key [AES_KEY_SIZE_256];
    uint32_t        keySize = 0;
    uint8_t         iv [AES_CFB_IV_SIZE];
    uint8_t         vector [TEST_VECTOR_OUTPUT_SIZE * 2];
    uint8_t         aesCfbOutput [TEST_VECTOR_OUTPUT_SIZE];
    uint8_t         decryptBuffer [TEST_VECTOR_OUTPUT_SIZE];
    uint8_t         inputBuffer [TEST_VECTOR_OUTPUT_SIZE] = {0};
    uint8_t         rc4Key = 0;

    // We can't encrypt just a zero buffer or we will end up with same result as OFB. As this is not a stream
    // cipher we need to change the input. These test vectors were generated by using an RC4 stream as input.
    // The RC4 stream is created by using a key of 0.
    Rc4XorWithKey( &rc4Key, sizeof(rc4Key), 0, inputBuffer, inputBuffer, sizeof(inputBuffer) );

    for( vectorIndex=0; vectorIndex<NUM_TEST_VECTORS; vectorIndex++ )
    {
        HexToBytes( gTestVectors[vectorIndex].KeyHex,        key, &keySize );
        HexToBytes( gTestVectors[vectorIndex].IvHex,         iv, NULL );
        HexToBytes( gTestVectors[vectorIndex].CipherTextHex, vector, NULL );

        AesCfbEncryptWithKey( key, keySize, iv, inputBuffer, aesCfbOutput, TEST_VECTOR_OUTPUT_SIZE );
        if( 0 != memcmp( aesCfbOutput, vector, TEST_VECTOR_OUTPUT_SIZE ) )
        {
            printf( "Test vector (index:%u) failed\n", vectorIndex );
            return false;
        }

        AesCfbDecryptWithKey( key, keySize, iv, aesCfbOutput, decryptBuffer, TEST_VECTOR_OUTPUT_SIZE );
        if( 0 != memcmp( decryptBuffer, inputBuffer, TEST_VECTOR_OUTPUT_SIZE ) )
        {
            printf( "Test vector (index:%u) failed decrypt\n", vectorIndex );
            return false;
        }
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  TestLargeVector
//
//  Tests AES OFB against a known large vector (of 1 million bytes). We check it against a known SHA-1 hash of
//  the output.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
static
bool
    TestLargeVector
    (
        void
    )
{

//dd if=/dev/zero iflag=count_bytes count=1000000 status=none | openssl enc -rc4 -K 0 | openssl enc -aes-128-cfb -K 00001111222233334444555566667777 -iv 88889999aaaabbbbccccddddeeeeffff | head -c 1000000 | openssl sha1
//(stdin)= 0df61cb501a01b08af38993be113911f2b0ed365

    uint8_t const*  key = (uint8_t const*)"\x00\x00\x11\x11\x22\x22\x33\x33\x44\x44\x55\x55\x66\x66\x77\x77";
    uint8_t const*  iv = (uint8_t const*)"\x88\x88\x99\x99\xaa\xaa\xbb\xbb\xcc\xcc\xdd\xdd\xee\xee\xff\xff";
    uint8_t const*  sha1Hash = (uint8_t const*)"\x0d\xf6\x1c\xb5\x01\xa0\x1b\x08\xaf\x38\x99\x3b\xe1\x13\x91\x1f\x2b\x0e\xd3\x65";
    uint32_t const  numBytesToGenerate = 1000000;
    uint8_t const   rc4Key = 0;

    uint8_t*        buffer = malloc( numBytesToGenerate );
    uint8_t*        buffer2 = malloc( numBytesToGenerate );
    uint32_t        amountLeft = numBytesToGenerate;
    uint32_t        chunkSize;
    Sha1Context     sha1Context;
    AesCfbContext   aesCfbContext;
    SHA1_HASH       calcSha1;
    uint32_t        offset;
    SHA1_HASH       initialInputSha1;

    // Encrypt in one go first.
    // Generate the Rc4 stream to encrypt
    memset( buffer, 0, numBytesToGenerate );
    Rc4XorWithKey( &rc4Key, 1, 0, buffer, buffer, numBytesToGenerate );
    Sha1Calculate( buffer, numBytesToGenerate, &initialInputSha1 );

    AesCfbEncryptWithKey( key, AES_KEY_SIZE_128, iv, buffer, buffer2, numBytesToGenerate );

    Sha1Initialise( &sha1Context );
    Sha1Update( &sha1Context, buffer2, numBytesToGenerate );
    Sha1Finalise( &sha1Context, &calcSha1 );

    if( 0 != memcmp( &calcSha1, sha1Hash, SHA1_HASH_SIZE ) )
    {
        printf( "Large test vector failed (1)\n" );
        return false;
    }

    // Now decrypt the buffer to verify it goes back to the original.
    AesCfbDecryptWithKey( key, AES_KEY_SIZE_128, iv, buffer, buffer2, numBytesToGenerate );
    Sha1Calculate( buffer, numBytesToGenerate, &calcSha1 );

    if( 0 != memcmp( &calcSha1, &initialInputSha1, SHA1_HASH_SIZE ) )
    {
        printf( "Large test vector failed decrypting\n" );
        return false;
    }

    memset( buffer, 0, numBytesToGenerate );

    // Now encrypt in smaller pieces (10000 bytes at a time)
    Sha1Initialise( &sha1Context );
    AesCfbInitialiseWithKey( &aesCfbContext, key, AES_KEY_SIZE_128, iv );

    memset( buffer, 0, numBytesToGenerate );
    Rc4XorWithKey( &rc4Key, 1, 0, buffer, buffer, numBytesToGenerate );
    offset = 0;

    while( amountLeft > 0 )
    {
        chunkSize = MIN( amountLeft, 10000 );
        AesCfbEncrypt( &aesCfbContext, buffer+offset, buffer+offset, chunkSize );
        Sha1Update( &sha1Context, buffer+offset, chunkSize );
        amountLeft -= chunkSize;
        offset += chunkSize;
    }

    Sha1Finalise( &sha1Context, &calcSha1 );

    if( 0 != memcmp( &calcSha1, sha1Hash, SHA1_HASH_SIZE ) )
    {
        printf( "Large test vector failed (2)\n" );
        return false;
    }

    return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  PUBLIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  TestAesOfb
//
//  Test AES CFB algorithm
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool
    TestAesCfb
    (
        void
    )
{
    bool        totalSuccess = true;
    bool        success;

    success = TestVectors( );
    if( !success ) { totalSuccess = false; }

    success = TestLargeVector( );
    if( !success ) { totalSuccess = false; }

    return totalSuccess;
}
