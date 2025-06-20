////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  WjCryptLib_AesOfb
//
//  Implementation of AES OFB stream cipher.
//
//  Depends on: CryptoLib_Aes
//
//  AES OFB is a stream cipher using the AES block cipher in output feedback mode.
//  This implementation works on both little and big endian architectures.
//
//  This is free and unencumbered software released into the public domain - January 2018 waterjuice.org
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  IMPORTS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <stdint.h>
#include "WjCryptLib_Aes.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  TYPES
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#define AES_OFB_IV_SIZE             AES_BLOCK_SIZE

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  TYPES
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// AesOfbContext
// Do not modify the contents of this structure directly.
typedef struct
{
    AesContext      Aes;
    uint8_t         CurrentCipherBlock [AES_BLOCK_SIZE];
    uint32_t        IndexWithinCipherBlock;
} AesOfbContext;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  PUBLIC FUNCTIONS
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesOfbInitialise
//
//  Initialises an AesOfbContext with an already initialised AesContext and a IV. This function can quickly be used
//  to change the IV without requiring the more lengthy processes of reinitialising an AES key.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    AesOfbInitialise
    (
        AesOfbContext*      Context,                // [out]
        AesContext const*   InitialisedAesContext,  // [in]
        uint8_t const       IV [AES_OFB_IV_SIZE]    // [in]
    );

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesOfbInitialiseWithKey
//
//  Initialises an AesOfbContext with an AES Key and an IV. This combines the initialising an AES Context and then
//  running AesOfbInitialise. KeySize must be 16, 24, or 32 (for 128, 192, or 256 bit key size)
//  Returns 0 if successful, or -1 if invalid KeySize provided
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int
    AesOfbInitialiseWithKey
    (
        AesOfbContext*      Context,                // [out]
        uint8_t const*      Key,                    // [in]
        uint32_t            KeySize,                // [in]
        uint8_t const       IV [AES_OFB_IV_SIZE]    // [in]
    );

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesOfbXor
//
//  XORs the stream of byte of the AesOfbContext from its current stream position onto the specified buffer. This will
//  advance the stream index by that number of bytes.
//  Use once over data to encrypt it. Use it a second time over the same data from the same stream position and the
//  data will be decrypted.
//  InBuffer and OutBuffer can point to the same location for in-place encrypting/decrypting
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    AesOfbXor
    (
        AesOfbContext*      Context,                // [in out]
        void const*         InBuffer,               // [in]
        void*               OutBuffer,              // [out]
        uint32_t            Size                    // [in]
    );

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesOfbOutput
//
//  Outputs the stream of byte of the AesOfbContext from its current stream position. This will advance the stream
//  index by that number of bytes.
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void
    AesOfbOutput
    (
        AesOfbContext*      Context,                // [in out]
        void*               Buffer,                 // [out]
        uint32_t            Size                    // [in]
    );

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  AesOfbXorWithKey
//
//  This function combines AesOfbInitialiseWithKey and AesOfbXor. This is suitable when encrypting/decypting data in
//  one go with a key that is not going to be reused.
//  This will used the provided Key and IV and generate a stream that is XORed over Buffer.
//  InBuffer and OutBuffer can point to the same location for inplace encrypting/decrypting
//  Returns 0 if successful, or -1 if invalid KeySize provided
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
int
    AesOfbXorWithKey
    (
        uint8_t const*      Key,                    // [in]
        uint32_t            KeySize,                // [in]
        uint8_t const       IV [AES_OFB_IV_SIZE],   // [in]
        void const*         InBuffer,               // [in]
        void*               OutBuffer,              // [out]
        uint32_t            BufferSize              // [in]
    );

#ifdef __cplusplus
}
#endif
