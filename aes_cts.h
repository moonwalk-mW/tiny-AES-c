/***************************************************************************************
* Filename: aes_cts.h
* Date: 8/26/2022
* 
* Extends tiny-AES-c to implement CBC Ciphertext Stealing mode.
* https://github.com/kokke/tiny-AES-C
* Refer to NIST SP 800-38A for specification information.
* https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a-add.pdf
*
*
* Need to make 3 changes to Kokke's files aes.c and aes.h
* 1) aes.c -> change "static void InvCipher..." to "void InvCipher..." (make non-static)
* 2) aes.h -> create function prototype for "void InvCipher..."
* 3) Move "typedef uint8_t state_t[4][4];" from aes.c to aes.h
***************************************************************************************/

#ifndef _AES_CTS_H_
#define _AES_CTS_H_

#include <stdint.h>
#include <stddef.h>
#include "aes.h"


// CBC enables tiny-AES-c encryption in CBC-mode of operation.
// CBC-CS uses use CBC Mode functions, so enable it
#ifndef CBC
  #define CBC 1 
#endif

#ifndef ECB
  #define ECB 1 
#endif


/****************************************************************************
* These functions implement the CBC-CS1 algorithm outlined in NIST SP800-38A.
* Encrypt takes a plaintext message in 'buf' with 'length' and returns a 
* CBC-CS1 encrypted message in 'buf'.
*
* Decrypt takes a CBC-CS1 encrypted message in 'buf' with 'length' and returns
* the decrypted plaintext message in 'buf'.
*
* Parameters:
*  ctx: pointer to an AES_ctx struct
*  buf: pointer to buffer containing the message to encrypt or decrypt
*  length: number of uint8_t-sized data in buf (length of the message)
*
* CS1 does not swap Cn-1 and Cn
****************************************************************************/
void AES_CBC_CS1_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CBC_CS1_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);


/****************************************************************************
* These functions implement the CBC-CS2 algorithm outlined in NIST SP800-38A.
* Encrypt takes a plaintext message in 'buf' with 'length' and returns a 
* CBC-CS2 encrypted message in 'buf'.
*
* Decrypt takes a CBC-CS2 encrypted message in 'buf' with 'length' and returns
* the decrypted plaintext message in 'buf'.
*
* Parameters:
*  ctx: pointer to an AES_ctx struct
*  buf: pointer to buffer containing the message to encrypt or decrypt
*  length: number of uint8_t-sized data in buf (length of the message)
*
* CS2 swaps Cn-1 and Cn if len(Cn) < AES_BLOCKLEN and is a non-empty block
****************************************************************************/
void AES_CBC_CS2_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CBC_CS2_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);


/****************************************************************************
* These functions implement the CBC-CS3 algorithm outlined in NIST SP800-38A.
* Encrypt takes a plaintext message in 'buf' with 'length' and returns a 
* CBC-CS3 encrypted message in 'buf'.
*
* Decrypt takes a CBC-CS3 encrypted message in 'buf' with 'length' and returns
* the decrypted plaintext message in 'buf'.
*
* Parameters:
*  ctx: pointer to an AES_ctx struct
*  buf: pointer to buffer containing the message to encrypt or decrypt
*  length: number of uint8_t-sized data in buf (length of the message)
*
* CS3 Always swaps Cn-1 and Cn regardless of final block size
****************************************************************************/
void AES_CBC_CS3_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CBC_CS3_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

void AES_ECB_CS1_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_ECB_CS1_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_ECB_CS2_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_ECB_CS2_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_ECB_CS3_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_ECB_CS3_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

#endif // _AES_CTS_H_
