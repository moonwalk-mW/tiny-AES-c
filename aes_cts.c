/*****************************************************************************
* Filename: aes_cts.c
* Date: 8/26/2022
* 
* Extends tiny-AES-c to implement CBC & ECB Ciphertext Stealing modes
* https://github.com/kokke/tiny-AES-C
* Refer to NIST SP 800-38A for specification information.
* https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a-add.pdf
*
*
* Plaintext message size does not have to be a multiple of AES_BLOCKLEN
* We assume len(message) >= AES_BLOCKLEN
*
* Future: remove #include stdlib.h and references to calloc and replace with 
* local array memset to 0, to reduce filesize.
******************************************************************************/


/*****************************************************************************/
/* Includes:                                                                 */
/*****************************************************************************/
#include <string.h> //for memcpy
#include <stdlib.h> //for calloc & free
#include <stdint.h>
#include "aes_cts.h"
#include "aes.h" //access tiny-aes-c functions


/*****************************************************************************/
/* Private functions:                                                        */
/*****************************************************************************/

/****************************************************************************
* Swap the last two blocks, Cn-1 and Cn, for CBC-CS2 and -CS3 encryption,
* as outlined in NIST SP800-38A, to form C1||C2||...||Cn-2||Cn||Cn-1*
* 
* Encrypt swaps the Cn-1 and Cn blocks after the message is encrypted and
* returns them in buf.
*
* Parameters:
*  buf: pointer to buffer containing the message to encrypt
*  length: number of uint8_t-sized data in buf (length of the message)
*          length > AES_BLOCKLEN
*  d: length of the final block
****************************************************************************/
static void AES_CS_encrypt_swap_blocks(uint8_t* buf, size_t length, uint8_t d)
{
  uint8_t temp[AES_BLOCKLEN]; //temp buffer to hold (Cn-1)*
  uint8_t idx_Cn_1 = length - d - AES_BLOCKLEN; //index of (Cn-1)* in buf
  uint8_t i;
  for (i = 0; i < AES_BLOCKLEN; ++i) //copy (Cn-1)* to temp
  { 
    temp[i] = buf[idx_Cn_1 + i];
  }
    
  for(i = 0; i < d; ++i) //copy Cn to (Cn-1)* blockspace
  {
    buf[idx_Cn_1 + i] = buf[idx_Cn_1 + AES_BLOCKLEN + i];
  }
    
  for(i = 0; i < AES_BLOCKLEN; ++i)//copy (Cn-1)* in temp to Cn blockspace
  {
    buf[idx_Cn_1 + d + i] = temp[i];
  }
}


/****************************************************************************
* Swap the last two blocks, Cn-1 and Cn, for CBC-CS2 and -CS3 decryption,
* as outlined in NIST SP800-38A, to form C1||C2...||Cn-2||Cn-1||Cn. This step
* occurs prior to decrypting.
* 
* Decrypt swaps the Cn-1 and Cn blocks before the message is decrypted and
* returns them in buf.
*
* Parameters:
*  buf: pointer to buffer containing the message to decrypt
*  length: number of uint8_t-sized data in buf (length of the message)
*          length > AES_BLOCKLEN
*  d: length of the final block
****************************************************************************/
static void AES_CS_decrypt_swap_blocks(uint8_t* buf, size_t length, uint8_t d)
{
  //Step 3 - Let C' = C1||C2||...||Cn*||Cn-1
  uint8_t temp[AES_BLOCKLEN]; //temp buffer to hold Cn-1
  uint8_t i;
  uint8_t idx_Cn_1 = length - d - AES_BLOCKLEN;
    
  for (i = 0; i < AES_BLOCKLEN; ++i) //copy Cn_1 to temp
  { 
    temp[i] = buf[idx_Cn_1 + d + i];
  }
    
  for(i = 0; i < d; ++i) //copy Cn-1 to Cn blockspace
  {
    buf[idx_Cn_1 + AES_BLOCKLEN + i] = buf[idx_Cn_1 + i];
  }
    
  for(i = 0; i < AES_BLOCKLEN; ++i)//copy Cn in temp to Cn-1 blockspace
  {
    buf[idx_Cn_1 + i] = temp[i];
  }
}


/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/

//Encrypt a plaintext message of variable length using AES-CBC-CS1 mode
//We assume length >= AES_BLOCKEN
void AES_CBC_CS1_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t d = length % AES_BLOCKLEN; //calculate length of final block (step 1)

  //buffer is a multiple of AES_BLOCKLEN, just call Encrypt and be done
  if (d == 0)
  {
    AES_CBC_encrypt_buffer(ctx, buf, length);
    return;
  }

  //buffer isn't a multiple of AES_BLOCKLEN, pad with Zeros (step 2)
  uint8_t * fullBuf = NULL; //temporary buffer to work with while we pad and encrypt
  uint8_t fullSize = length + AES_BLOCKLEN - d; //length of fullBuf accounting for message length and padding length

  fullBuf = calloc(fullSize, sizeof(uint8_t)); //create buffer we'll encrypt the data in (use calloc for zero padding)
  memcpy(fullBuf, buf, length); //copy plaintext buf (of length 'length') to new "fullBuf", which accounts for any necessary padding that was created by our 'calloc' call above
  
  uint8_t copyBytes = length - AES_BLOCKLEN - d; //calculate length of C1...Cn-2
  
  AES_CBC_encrypt_buffer(ctx, fullBuf, fullSize); //encrypt (step 3)
  
  //now remove any encrypted bytes from Cn-1* (penultimate block) that were stolen (step 4)
  memcpy(buf, fullBuf, copyBytes); //get C1...Cn-2
  memcpy(buf + copyBytes, fullBuf + copyBytes, d); //get MSBd(Cn-1)

  //get final block Cn (step 5)
  //skip over (AES_BLOCKLEN - d) number of bytes in block Cn-1, and get the last block
  memcpy(buf + copyBytes + d, fullBuf + copyBytes + AES_BLOCKLEN, AES_BLOCKLEN); //step 5

  free(fullBuf);
  return;
}


//Decrypt an AES-CBC-CS1 encrypted message of variable length
//We assume length >= AES_BLOCKEN
void AES_CBC_CS1_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t * fullBuf = NULL;
  uint8_t d = length % AES_BLOCKLEN; //calculate length of final block (step 1)
  
  //buffer is a multiple of AES_BLOCKLEN, just call Decrypt and be done
  if (d == 0)
  {
    AES_CBC_decrypt_buffer(ctx, buf, length);
    return;
  }

  //step 2
  InvCipher((state_t*)(buf + length - AES_BLOCKLEN), ctx->RoundKey); //decrypt last block, Cn
  uint8_t * Zp = buf + length - AES_BLOCKLEN; //Z* = MSBd(INVCIPH(Cn)). note: len(Z*) is d
  uint8_t * Zpp = Zp + d; //Z** = LSB(b-d)(INVCIPH(Cn)). note: len(Z**) is AES_BLOCKLEN-d (b-d)

  //step 3
  fullBuf = calloc(length, sizeof(uint8_t)); //make our temporary buffer to decrypt in
  memcpy(fullBuf, buf, length-AES_BLOCKLEN); //copy C1...Cn-1
  memcpy(fullBuf + length - AES_BLOCKLEN, Zpp, (AES_BLOCKLEN - d)); // Cn-1 = (Cn-1)* || Z**

  //step 4
  AES_CBC_decrypt_buffer(ctx, fullBuf, length-d); //decrypt C1,C2,...,Cn-1
  
  //step 5: Pn* = (Cn-1)* ^ Z*
  //This finishes the decrypt of the final block we started in Step 2
  uint8_t i;
  for (i = 0; i < d; ++i) // Z* has len d
  {
    fullBuf[length - d + i] = buf[length - AES_BLOCKLEN - d + i] ^ Zp[i];
  }

  //step 6: return P1 || P2 ||...||Pn-1||Pn*
  memcpy(buf, fullBuf, length);
  free(fullBuf);
 
	return;
}


//Encrypt a plaintext message of variable length using AES-CBC-CS2 mode
//We assume length > AES_BLOCKEN
void AES_CBC_CS2_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t d = length % AES_BLOCKLEN; //calculate length of final block (step 1)

  //Step 2 - Apply CBC-CS1 Encrypt to the plaintext
  AES_CBC_CS1_encrypt_buffer(ctx, buf, length);

  //Step 3:
  //if d < AES_BLOCKLEN (b) return C1||C2||...||Cn||(Cn-1)*
  //else return C1||C2||...||(Cn-1)*||Cn
  if(d != 0)
  {
    AES_CS_encrypt_swap_blocks(buf, length, d);
  }

  return;
}


//Decrypt an AES-CBC-CS2 encrypted message of variable length
//We assume length > AES_BLOCKEN
void AES_CBC_CS2_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t d = length % AES_BLOCKLEN; //calculate length of final block (step 1)

  //Step 2 - Apply CBC-CS1 Decrypt to the ciphertext since len(Cn) == AES_BLOCKLEN
  if (d == 0)
  {
    AES_CBC_CS1_decrypt_buffer(ctx, buf, length);
    return;
  }
  
  //Step 3 - swap Cn & Cn-1
  AES_CS_decrypt_swap_blocks(buf, length, d);

  //Step 4
  AES_CBC_CS1_decrypt_buffer(ctx, buf, length);

  return;
}


//Encrypt a plaintext message of variable length using AES-CBC-CS3 mode
//We assume length > AES_BLOCKEN
void AES_CBC_CS3_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t d = length % AES_BLOCKLEN; //calculate length of last block
  AES_CBC_CS1_encrypt_buffer(ctx, buf, length); //encrypt with CBC-CS1 to produce C1||C2||...||Cn-1*||Cn
  AES_CS_encrypt_swap_blocks(buf, length, d); //swap Cn-1* and Cn to produce C1||C2||...||Cn||Cn-1*
  
  return;
}


//Decrypt a plaintext message of variable length using AES-CBC-CS3 mode
//We assume length > AES_BLOCKEN
void AES_CBC_CS3_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t d = length % AES_BLOCKLEN; //calculate length of last block
  AES_CS_decrypt_swap_blocks(buf, length, d); //swap Cn-1* and Cn to produce C1||C2||...||Cn*||Cn-1
  AES_CBC_CS1_decrypt_buffer(ctx, buf, length); //decrypt with CBC-CS1 to produce P
    
  return;
}


//Encrypt a plaintext message of variable length using AES-ECB-CS1 mode
//We assume length >= AES_BLOCKEN
void AES_ECB_CS1_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t d = length % AES_BLOCKLEN; //calculate length of final block (step 1)

  //buffer is a multiple of AES_BLOCKLEN, just call Encrypt and be done
  if (d == 0)
  {
    uint8_t numBlocks = length / AES_BLOCKLEN;
    uint8_t i;
    for (i = 0; i < numBlocks; ++i)
    {
      AES_ECB_encrypt(ctx, buf + (i * AES_BLOCKLEN));
    }
    return;
  }

  //buffer isn't a multiple of AES_BLOCKLEN, pad with Zeros (step 2)
  uint8_t * fullBuf = NULL; //temporary buffer to work with while we pad and encrypt
  uint8_t fullSize = length + AES_BLOCKLEN - d; //length of fullBuf accounting for message length and padding length

  fullBuf = calloc(fullSize, sizeof(uint8_t)); //create buffer we'll encrypt the data in (use calloc for zero padding)
  memcpy(fullBuf, buf, length); //copy plaintext buf (of length 'length') to new "fullBuf", which accounts for any necessary padding that was created by our 'calloc' call above
  
  uint8_t copyBytes = length - AES_BLOCKLEN - d; //calculate length of C1...Cn-2
  
  uint8_t numBlocks = length / AES_BLOCKLEN;
  uint8_t i;
  for (i = 0; i < numBlocks; ++i)
  {
    AES_ECB_encrypt(ctx, fullBuf + (i * AES_BLOCKLEN));
  }
    
  uint8_t Cn[AES_BLOCKLEN];
  memcpy(Cn, fullBuf + (numBlocks * AES_BLOCKLEN), d); //copy MSBd(Pn) to temp Cn array
  memcpy(Cn + d, fullBuf + copyBytes + d, AES_BLOCKLEN - d); //append LSBb-d(Cn-1) to temp Cn array
  
  AES_ECB_encrypt(ctx, Cn); //encrypt Cn
  memcpy(fullBuf + copyBytes + AES_BLOCKLEN, Cn, AES_BLOCKLEN); //place Cn in fullBuf at correct offset
  
  //now remove any encrypted bytes from Cn-1* (penultimate block) that were stolen (step 4)
  memcpy(buf, fullBuf, copyBytes); //get C1...Cn-2
  memcpy(buf + copyBytes, fullBuf + copyBytes, d); //get MSBd(Cn-1)

  //get final block Cn (step 5)
  //skip over (AES_BLOCKLEN - d) number of bytes in block Cn-1, and get the last block
  memcpy(buf + copyBytes + d, fullBuf + copyBytes + AES_BLOCKLEN, AES_BLOCKLEN); //step 5

  free(fullBuf);
  return;
}


//Decrypt an AES-ECB-CS1 encrypted message of variable length
//We assume length >= AES_BLOCKEN
void AES_ECB_CS1_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t * fullBuf = NULL;
  uint8_t d = length % AES_BLOCKLEN; //calculate length of final block (step 1)
  
  //buffer is a multiple of AES_BLOCKLEN, just call Decrypt and be done
  if (d == 0)
  {
    uint8_t numBlocks = length / AES_BLOCKLEN;
    uint8_t i;
    for (i = 0; i < numBlocks; ++i)
    {
      AES_ECB_decrypt(ctx, buf + (i * AES_BLOCKLEN));
    }
    return;
  }

  //step 2
  InvCipher((state_t*)(buf + length - AES_BLOCKLEN), ctx->RoundKey); //decrypt last block, Cn
  uint8_t * Zp = buf + length - AES_BLOCKLEN; //Z* = MSBd(INVCIPH(Cn)). note: len(Z*) is d
  uint8_t * Zpp = Zp + d; //Z** = LSB(b-d)(INVCIPH(Cn)). note: len(Z**) is AES_BLOCKLEN-d (b-d)

  //step 3
  fullBuf = calloc(length, sizeof(uint8_t)); //make our temporary buffer to decrypt in
  memcpy(fullBuf, buf, length-AES_BLOCKLEN); //copy C1...Cn-1
  memcpy(fullBuf + length - AES_BLOCKLEN, Zpp, (AES_BLOCKLEN - d)); // Cn-1 = (Cn-1)* || Z**

  uint8_t numBlocks = length / AES_BLOCKLEN;
  uint8_t i;
  for (i = 0; i < numBlocks; ++i)
  {
    AES_ECB_decrypt(ctx, fullBuf + (i * AES_BLOCKLEN)); //decrypt C1,C2,...,Cn-1
  }
    
  //copy Cn to correct spot
  for (i = 0; i < d; ++i) // Z* has len d
  {
    fullBuf[length - d + i] = buf[length - AES_BLOCKLEN + i];
  }

  //step 6: return P1 || P2 ||...||Pn-1||Pn*
  memcpy(buf, fullBuf, length);
  free(fullBuf);
 
	return;
}

//Encrypt a plaintext message of variable length using AES-CBC-CS2 mode
//We assume length > AES_BLOCKEN
void AES_ECB_CS2_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t d = length % AES_BLOCKLEN; //calculate length of final block (step 1)

  //Step 2 - Apply CBC-CS1 Encrypt to the plaintext
  AES_ECB_CS1_encrypt_buffer(ctx, buf, length);

  //Step 3:
  //if d < AES_BLOCKLEN (b) return C1||C2||...||Cn||(Cn-1)*
  //else return C1||C2||...||(Cn-1)*||Cn
  if(d != 0)
  {
    AES_CS_encrypt_swap_blocks(buf, length, d);
  }

  return;
}


//Decrypt an AES-CBC-CS2 encrypted message of variable length
//We assume length > AES_BLOCKEN
void AES_ECB_CS2_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t d = length % AES_BLOCKLEN; //calculate length of final block (step 1)

  //Step 2 - Apply CBC-CS1 Decrypt to the ciphertext since len(Cn) == AES_BLOCKLEN
  if (d == 0)
  {
    AES_ECB_CS1_decrypt_buffer(ctx, buf, length);
    return;
  }
  
  //Step 3 - swap Cn & Cn-1
  AES_CS_decrypt_swap_blocks(buf, length, d);

  //Step 4
  AES_ECB_CS1_decrypt_buffer(ctx, buf, length);

  return;
}


//Encrypt a plaintext message of variable length using AES-CBC-CS3 mode
//We assume length > AES_BLOCKEN
void AES_ECB_CS3_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t d = length % AES_BLOCKLEN; //calculate length of last block
  AES_ECB_CS1_encrypt_buffer(ctx, buf, length); //encrypt with CBC-CS1 to produce C1||C2||...||Cn-1*||Cn
  AES_CS_encrypt_swap_blocks(buf, length, d); //swap Cn-1* and Cn to produce C1||C2||...||Cn||Cn-1*
  
  return;
}


//Decrypt a plaintext message of variable length using AES-CBC-CS3 mode
//We assume length > AES_BLOCKEN
void AES_ECB_CS3_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
  uint8_t d = length % AES_BLOCKLEN; //calculate length of last block
  AES_CS_decrypt_swap_blocks(buf, length, d); //swap Cn-1* and Cn to produce C1||C2||...||Cn*||Cn-1
  AES_ECB_CS1_decrypt_buffer(ctx, buf, length); //decrypt with CBC-CS1 to produce P
    
  return;
}
