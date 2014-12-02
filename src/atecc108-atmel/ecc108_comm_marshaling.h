#ifdef __cplusplus
extern "C" {
#endif
/** \file
 *  \brief  Definitions and Prototypes for Command Marshaling Layer of ECC108 Library
 *  \author Atmel Crypto Products
 *  \date   January 16, 2014

* \copyright Copyright (c) 2014 Atmel Corporation. All rights reserved.
*
* \atmel_crypto_device_library_license_start
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* 3. The name of Atmel may not be used to endorse or promote products derived
*    from this software without specific prior written permission.
*
* 4. This software may only be redistributed and used in connection with an
*    Atmel integrated circuit.
*
* THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED
* WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
* EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
* ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* \atmel_crypto_device_library_license_stop
 *
   <table>
     <caption align="top">Command Packet Structure</caption>
     <tr>
       <th width=25%>Byte #</th> <th width=25%>Name</th> <th>Meaning</th>
     </tr>
     <tr>
       <td>0</td>
       <td>Count</td>
       <td>Number of bytes in the packet, includes the count byte, body and the checksum</td>
     </tr>
     <tr>
       <td>1</td>
       <td>Op-Code</td>
       <td>Indicates type of command</td>
     </tr>
     <tr>
       <td>2</td>
       <td>Parameter 1</td>
       <td>mode, zone, etc.</td>
     </tr>
     <tr>
       <td>3 and 4</td>
       <td>Parameter 2</td>
       <td>key id, address, etc.</td>
     </tr>
     <tr>
       <td>5 to n</td>
       <td>data (not for every command)</td>
       <td>challenge, pass-through, etc.</td>
     </tr>
     <tr>
       <td>n+1 to n+2</td>
       <td>Checksum</td>
       <td>Checksum of the command packet</td>
     </tr>
   </table>

   <table>
     <caption align="top">Response Packet Structure</caption>
     <tr>
       <th width=25%>Byte #</th> <th width=25%>Name</th> <th>Meaning</th>
     </tr>
     <tr>
       <td>0</td>
       <td>Count</td>
       <td>Number of bytes in the packet, includes the count byte, body and the checksum</td>
     </tr>
     <tr>
       <td>1</td>
       <td>Status / Data</td>
       <td>Status or first data byte</td>
     </tr>
     <tr>
       <td>2 to n</td>
       <td>More data bytes</td>
       <td>random, challenge response, read data, etc.</td>
     </tr>
     <tr>
       <td>n+1 to n+2</td>
       <td>Checksum</td>
       <td>Checksum of the command packet</td>
     </tr>
   </table>
 */

#ifndef ECC108_COMM_MARSHALING_H
#   define ECC108_COMM_MARSHALING_H

#include "ecc108_comm.h" // definitions and declarations for the communication module


/** \defgroup atecc108_command_marshaling Module 01: Command Marshaling
 \brief
 * A function is provided for every ATECC108 command in the final release. These functions check the parameters,
 * assemble a command packet, send it, receive its response, and return the status of the operation
 * and the response.
@{ */

/** \name Codes for ATECC108 Commands
@{ */
#define ECC108_CHECKMAC                 ((uint8_t) 0x28)       //!< CheckMac command op-code
#define ECC108_DERIVE_KEY               ((uint8_t) 0x1C)       //!< DeriveKey command op-code
#define ECC108_INFO                     ((uint8_t) 0x30)       //!< Info command op-code
#define ECC108_GENDIG                   ((uint8_t) 0x15)       //!< GenDig command op-code
#define ECC108_GENKEY                   ((uint8_t) 0x40)       //!< GenKey command op-code
#define ECC108_HMAC                     ((uint8_t) 0x11)       //!< HMAC command op-code
#define ECC108_LOCK                     ((uint8_t) 0x17)       //!< Lock command op-code
#define ECC108_MAC                      ((uint8_t) 0x08)       //!< MAC command op-code
#define ECC108_NONCE                    ((uint8_t) 0x16)       //!< Nonce command op-code
#define ECC108_PAUSE                    ((uint8_t) 0x01)       //!< Pause command op-code
#define ECC108_PRIVWRITE                ((uint8_t) 0x46)       //!< PrivWrite command op-code
#define ECC108_RANDOM                   ((uint8_t) 0x1B)       //!< Random command op-code
#define ECC108_READ                     ((uint8_t) 0x02)       //!< Read command op-code
#define ECC108_SIGN                     ((uint8_t) 0x41)       //!< Sign command op-code
#define ECC108_UPDATE_EXTRA             ((uint8_t) 0x20)       //!< UpdateExtra command op-code
#define ECC108_VERIFY                   ((uint8_t) 0x45)       //!< GenKey command op-code
#define ECC108_WRITE                    ((uint8_t) 0x12)       //!< Write command op-code
/** @} */


/** \name Definitions of Data and Packet Sizes
@{ */
#define ECC108_RSP_SIZE_VAL             ((uint8_t)  7)         //!< size of response packet containing four bytes of data
#define ECC108_KEY_SIZE                 (32)                   //!< size of key
#define ECC108_KEY_COUNT                (16)                   //!< number of keys
#define ECC108_CONFIG_SIZE              (128)                   //!< size of configuration zone
#define ECC108_OTP_SIZE                 (64)                   //!< size of OTP zone
#define ECC108_DATA_SIZE                (ECC108_KEY_COUNT * ECC108_KEY_SIZE) //!< size of data zone
/** @} */

/** \name Definitions for Command Parameter Ranges
@{ */
#define ECC108_KEY_ID_MAX               ((uint8_t) 15)         //!< maximum value for key id
#define ECC108_OTP_BLOCK_MAX            ((uint8_t)  1)         //!< maximum value for OTP block
/** @} */

/** \name Definitions for Indexes Common to All Commands
@{ */
#define ECC108_COUNT_IDX                ( 0)                   //!< command packet index for count
#define ECC108_OPCODE_IDX               ( 1)                   //!< command packet index for op-code
#define ECC108_PARAM1_IDX               ( 2)                   //!< command packet index for first parameter
#define ECC108_PARAM2_IDX               ( 3)                   //!< command packet index for second parameter
#define ECC108_DATA_IDX                 ( 5)                   //!< command packet index for data load
/** @} */

/** \name Definitions for Zone and Address Parameters
@{ */
#define ECC108_ZONE_CONFIG              ((uint8_t)  0x00)      //!< Configuration zone
#define ECC108_ZONE_OTP                 ((uint8_t)  0x01)      //!< OTP (One Time Programming) zone
#define ECC108_ZONE_DATA                ((uint8_t)  0x02)      //!< Data zone
#define ECC108_ZONE_MASK                ((uint8_t)  0x03)      //!< Zone mask
#define ECC108_ZONE_COUNT_FLAG          ((uint8_t)  0x80)      //!< Zone bit 7 set: Access 32 bytes, otherwise 4 bytes.
#define ECC108_ZONE_ACCESS_4            ((uint8_t)     4)      //!< Read or write 4 bytes.
#define ECC108_ZONE_ACCESS_32           ((uint8_t)    32)      //!< Read or write 32 bytes.
#define ECC108_ADDRESS_MASK_CONFIG      (         0x001F)      //!< Address bits 5 to 7 are 0 for Configuration zone.
#define ECC108_ADDRESS_MASK_OTP         (         0x000F)      //!< Address bits 4 to 7 are 0 for OTP zone.
#define ECC108_ADDRESS_MASK             (         0x007F)      //!< Address bit 7 to 15 are always 0.
/** @} */

/** \name Definitions for ECC Key type
@{ */
#define ECC108_B283_KEY_TYPE            0                      //!< B283 NIST ECC key
#define ECC108_K283_KEY_TYPE            1                      //!< K283 NIST ECC key
#define ECC108_P256_KEY_TYPE            4                      //!< P256 NIST ECC key
/** @} */

/** \name Definitions for the CheckMac Command
@{ */
#define CHECKMAC_MODE_IDX               ECC108_PARAM1_IDX      //!< CheckMAC command index for mode
#define CHECKMAC_KEYID_IDX              ECC108_PARAM2_IDX      //!< CheckMAC command index for key identifier
#define CHECKMAC_CLIENT_CHALLENGE_IDX   ECC108_DATA_IDX        //!< CheckMAC command index for client challenge
#define CHECKMAC_CLIENT_RESPONSE_IDX    (37)                   //!< CheckMAC command index for client response
#define CHECKMAC_DATA_IDX               (69)                   //!< CheckMAC command index for other data
#define CHECKMAC_COUNT                  (84)                   //!< CheckMAC command packet size
#define CHECKMAC_MODE_CHALLENGE         ((uint8_t) 0x00)       //!< CheckMAC mode       0: first SHA block from key id
#define CHECKMAC_MODE_BLOCK2_TEMPKEY    ((uint8_t) 0x01)       //!< CheckMAC mode bit   0: second SHA block from TempKey
#define CHECKMAC_MODE_BLOCK1_TEMPKEY    ((uint8_t) 0x02)       //!< CheckMAC mode bit   1: first SHA block from TempKey
#define CHECKMAC_MODE_SOURCE_FLAG_MATCH ((uint8_t) 0x04)       //!< CheckMAC mode bit   2: match TempKey.SourceFlag
#define CHECKMAC_MODE_INCLUDE_OTP_64    ((uint8_t) 0x20)       //!< CheckMAC mode bit   5: include first 64 OTP bits
#define CHECKMAC_MODE_MASK              ((uint8_t) 0x27)       //!< CheckMAC mode bits 3, 4, 6, and 7 are 0.
#define CHECKMAC_CLIENT_CHALLENGE_SIZE  (32)                   //!< CheckMAC size of client challenge
#define CHECKMAC_CLIENT_RESPONSE_SIZE   (32)                   //!< CheckMAC size of client response
#define CHECKMAC_OTHER_DATA_SIZE        (13)                   //!< CheckMAC size of "other data"
#define CHECKMAC_CLIENT_COMMAND_SIZE    ( 4)                   //!< CheckMAC size of client command header size inside "other data"
/** @} */

/** \name Definitions for the DeriveKey Command
@{ */
#define DERIVE_KEY_RANDOM_IDX           ECC108_PARAM1_IDX      //!< DeriveKey command index for random bit
#define DERIVE_KEY_TARGETKEY_IDX        ECC108_PARAM2_IDX      //!< DeriveKey command index for target slot
#define DERIVE_KEY_MAC_IDX              ECC108_DATA_IDX        //!< DeriveKey command index for optional MAC
#define DERIVE_KEY_COUNT_SMALL          ECC108_CMD_SIZE_MIN    //!< DeriveKey command packet size without MAC
#define DERIVE_KEY_COUNT_LARGE          (39)                   //!< DeriveKey command packet size with MAC
#define DERIVE_KEY_RANDOM_FLAG          ((uint8_t) 4)          //!< DeriveKey 1. parameter; has to match TempKey.SourceFlag
#define DERIVE_KEY_MAC_SIZE             (32)                   //!< DeriveKey MAC size
/** @} */

/** \name Definitions for the GenDig Command
@{ */
#define GENDIG_ZONE_IDX                 ECC108_PARAM1_IDX      //!< GenDig command index for zone
#define GENDIG_KEYID_IDX                ECC108_PARAM2_IDX      //!< GenDig command index for key id
#define GENDIG_DATA_IDX                 ECC108_DATA_IDX        //!< GenDig command index for optional data
#define GENDIG_COUNT                    ECC108_CMD_SIZE_MIN    //!< GenDig command packet size without "other data"
#define GENDIG_COUNT_DATA               (11)                   //!< GenDig command packet size with "other data"
#define GENDIG_OTHER_DATA_SIZE          (4)                    //!< GenDig size of "other data"
#define GENDIG_ZONE_CONFIG              ((uint8_t) 0)          //!< GenDig zone id config
#define GENDIG_ZONE_OTP                 ((uint8_t) 1)          //!< GenDig zone id OTP
#define GENDIG_ZONE_DATA                ((uint8_t) 2)          //!< GenDig zone id data
/** @} */

/** \name Definitions for the GenKey Command
@{ */
#define GENKEY_MODE_IDX                 ECC108_PARAM1_IDX      //!< GenKey command index for mode
#define GENKEY_KEYID_IDX                ECC108_PARAM2_IDX      //!< GenKey command index for key id
#define GENKEY_DATA_IDX                 ( 5)                   //!< GenKey command index for other data
#define GENKEY_COUNT                    ECC108_CMD_SIZE_MIN    //!< GenKey command packet size without "other data"
#define GENKEY_COUNT_DATA               (10)                   //!< GenKey command packet size with "other data"
#define GENKEY_OTHER_DATA_SIZE          ( 3)                   //!< GenKey size of "other data"
#define GENKEY_MODE_MASK                ((uint8_t) 0x1C)       //!< GenKey mode bits 0 to 1 and 5 to 7 are 0
#define GENKEY_MODE_PRIVATE             ((uint8_t) 0x04)       //!< GenKey mode: private key generation
#define GENKEY_MODE_PUBLIC              ((uint8_t) 0x00)       //!< GenKey mode: public key calculation
#define GENKEY_MODE_DIGEST              ((uint8_t) 0x10)       //!< GenKey mode: digest calculation
#define GENKEY_MODE_ADD_DIGEST          ((uint8_t) 0x08)       //!< GenKey mode: additional digest calculation
/** @} */

/** \name Definitions for the HMAC Command
@{ */
#define HMAC_MODE_IDX                   ECC108_PARAM1_IDX      //!< HMAC command index for mode
#define HMAC_KEYID_IDX                  ECC108_PARAM2_IDX      //!< HMAC command index for key id
#define HMAC_COUNT                      ECC108_CMD_SIZE_MIN    //!< HMAC command packet size
#define HMAC_MODE_SOURCE_FLAG_MATCH     ((uint8_t) 0x04)       //!< HMAC mode bit 2: match TempKey.SourceFlag
#define HMAC_MODE_MASK                  ((uint8_t) 0x74)       //!< HMAC mode bits 0, 1, 3, and 7 are 0.
/** @} */

/** \name Definitions for the Info Command
@{ */
#define INFO_PARAM1_IDX                 ECC108_PARAM1_IDX      //!< Info command index for 1. parameter
#define INFO_PARAM2_IDX                 ECC108_PARAM2_IDX      //!< Info command index for 2. parameter
#define INFO_COUNT                      ECC108_CMD_SIZE_MIN    //!< Info command packet size
#define INFO_MODE_REVISION              ((uint8_t) 0x00)       //!< Info mode Revision
#define INFO_MODE_KEY_VALID             ((uint8_t) 0x01)       //!< Info mode KeyValid
#define INFO_MODE_STATE                 ((uint8_t) 0x02)       //!< Info mode State
#define INFO_MODE_GPIO                  ((uint8_t) 0x03)       //!< Info mode GPIO
#define INFO_MODE_MAX                   ((uint8_t) 0x03)       //!< Info mode maximum value
#define INFO_NO_STATE                   ((uint8_t) 0x00)       //!< Info mode is not the state mode.
#define INFO_OUTPUT_STATE_MASK          ((uint8_t) 0x01)       //!< Info output state mask
#define INFO_DRIVER_STATE_MASK          ((uint8_t) 0x02)       //!< Info driver state mask
#define INFO_PARAM2_MAX                 ((uint8_t) 0x03)       //!< Info param2 (state) maximum value
/** @} */

/** \name Definitions for the Lock Command
@{ */
#define LOCK_ZONE_IDX                   ECC108_PARAM1_IDX      //!< Lock command index for zone
#define LOCK_SUMMARY_IDX                ECC108_PARAM2_IDX      //!< Lock command index for summary
#define LOCK_COUNT                      ECC108_CMD_SIZE_MIN    //!< Lock command packet size
#define LOCK_ZONE_NO_CONFIG             ((uint8_t) 0x01)       //!< Lock zone is OTP or Data
#define LOCK_ZONE_NO_CRC                ((uint8_t) 0x80)       //!< Lock command: Ignore summary.
#define LOCK_ZONE_MASK                  (0xBF)                 //!< Lock parameter 1 bits 6 are 0.
/** @} */

/** \name Definitions for the MAC Command
@{ */
#define MAC_MODE_IDX                    ECC108_PARAM1_IDX      //!< MAC command index for mode
#define MAC_KEYID_IDX                   ECC108_PARAM2_IDX      //!< MAC command index for key id
#define MAC_CHALLENGE_IDX               ECC108_DATA_IDX        //!< MAC command index for optional challenge
#define MAC_COUNT_SHORT                 ECC108_CMD_SIZE_MIN    //!< MAC command packet size without challenge
#define MAC_COUNT_LONG                  (39)                   //!< MAC command packet size with challenge
#define MAC_MODE_CHALLENGE              ((uint8_t) 0x00)       //!< MAC mode       0: first SHA block from data slot
#define MAC_MODE_BLOCK2_TEMPKEY         ((uint8_t) 0x01)       //!< MAC mode bit   0: second SHA block from TempKey
#define MAC_MODE_BLOCK1_TEMPKEY         ((uint8_t) 0x02)       //!< MAC mode bit   1: first SHA block from TempKey
#define MAC_MODE_SOURCE_FLAG_MATCH      ((uint8_t) 0x04)       //!< MAC mode bit   2: match TempKey.SourceFlag
#define MAC_MODE_PASSTHROUGH            ((uint8_t) 0x07)       //!< MAC mode bit 0-2: pass-through mode
#define MAC_MODE_INCLUDE_OTP_88         ((uint8_t) 0x10)       //!< MAC mode bit   4: include first 88 OTP bits
#define MAC_MODE_INCLUDE_OTP_64         ((uint8_t) 0x20)       //!< MAC mode bit   5: include first 64 OTP bits
#define MAC_MODE_INCLUDE_SN             ((uint8_t) 0x40)       //!< MAC mode bit   6: include serial number
#define MAC_CHALLENGE_SIZE              (32)                   //!< MAC size of challenge
#define MAC_MODE_MASK                   ((uint8_t) 0x77)       //!< MAC mode bits 3 and 7 are 0.
/** @} */

/** \name Definitions for the Nonce Command
@{ */
#define NONCE_MODE_IDX                  ECC108_PARAM1_IDX      //!< Nonce command index for mode
#define NONCE_PARAM2_IDX                ECC108_PARAM2_IDX      //!< Nonce command index for 2. parameter
#define NONCE_INPUT_IDX                 ECC108_DATA_IDX        //!< Nonce command index for input data
#define NONCE_COUNT_SHORT               (27)                   //!< Nonce command packet size for 20 bytes of data
#define NONCE_COUNT_LONG                (39)                   //!< Nonce command packet size for 32 bytes of data
#define NONCE_MODE_MASK                 ((uint8_t) 0x03)       //!< Nonce mode bits 2 to 7 are 0.
#define NONCE_MODE_SEED_UPDATE          ((uint8_t) 0x00)       //!< Nonce mode: update seed
#define NONCE_MODE_NO_SEED_UPDATE       ((uint8_t) 0x01)       //!< Nonce mode: do not update seed
#define NONCE_MODE_INVALID              ((uint8_t) 0x02)       //!< Nonce mode 2 is invalid.
#define NONCE_MODE_PASSTHROUGH          ((uint8_t) 0x03)       //!< Nonce mode: pass-through
#define NONCE_MODE_RANDOM_OUT           ((uint16_t) 0x0000)    //!< Nonce mode: output RandOut or single byte of zero
#define NONCE_MODE_TEMPKEY_OUT          ((uint16_t) 0x0080)    //!< Nonce mode: output RandOut or single byte of zero
#define NONCE_NUMIN_SIZE                (20)                   //!< Nonce data length
#define NONCE_NUMIN_SIZE_PASSTHROUGH    (32)                   //!< Nonce data length in pass-through mode (mode = 3)
/** @} */

/** \name Definitions for the Pause Command
@{ */
#define PAUSE_SELECT_IDX                ECC108_PARAM1_IDX      //!< Pause command index for Selector
#define PAUSE_PARAM2_IDX                ECC108_PARAM2_IDX      //!< Pause command index for 2. parameter
#define PAUSE_COUNT                     ECC108_CMD_SIZE_MIN    //!< Pause command packet size
/** @} */

/** \name Definitions for the PrivWrite Command
@{ */
#define PRIVWRITE_ZONE_IDX              ECC108_PARAM1_IDX      //!< PrivWrite command index for zone
#define PRIVWRITE_KEYID_IDX             ECC108_PARAM2_IDX      //!< PrivWrite command index for KeyID
#define PRIVWRITE_VALUE_IDX             ( 5)                   //!< PrivWrite command index for value
#define PRIVWRITE_MAC_IDX               (41)                   //!< PrivWrite command index for MAC
#define PRIVWRITE_COUNT                 (75)                   //!< PrivWrite command packet size
#define PRIVWRITE_ZONE_MASK             ((uint8_t) 0x40)       //!< PrivWrite zone bits 0 to 5 and 7 are 0.
#define PRIVWRITE_MODE_ENCRYPT          ((uint8_t) 0x40)       //!< PrivWrite mode: encrypted
/** @} */

/** \name Definitions for the Random Command
@{ */
#define RANDOM_MODE_IDX                 ECC108_PARAM1_IDX      //!< Random command index for mode
#define RANDOM_PARAM2_IDX               ECC108_PARAM2_IDX      //!< Random command index for 2. parameter
#define RANDOM_COUNT                    ECC108_CMD_SIZE_MIN    //!< Random command packet size
#define RANDOM_SEED_UPDATE              ((uint8_t) 0x00)       //!< Random mode for automatic seed update
#define RANDOM_NO_SEED_UPDATE           ((uint8_t) 0x01)       //!< Random mode for no seed update
/** @} */

/** \name Definitions for the Read Command
@{ */
#define READ_ZONE_IDX                   ECC108_PARAM1_IDX      //!< Read command index for zone
#define READ_ADDR_IDX                   ECC108_PARAM2_IDX      //!< Read command index for address
#define READ_COUNT                      ECC108_CMD_SIZE_MIN    //!< Read command packet size
#define READ_ZONE_MASK                  ((uint8_t) 0x83)       //!< Read zone bits 2 to 6 are 0.
/** @} */

/** \name Definitions for the Sign Command
@{ */
#define SIGN_MODE_IDX                   ECC108_PARAM1_IDX      //!< Sign command index for mode
#define SIGN_KEYID_IDX                  ECC108_PARAM2_IDX      //!< Sign command index for key id
#define SIGN_COUNT                      ECC108_CMD_SIZE_MIN    //!< Sign command packet size
#define SIGN_MODE_MASK                  ((uint8_t) 0xC0)       //!< Sign mode bits 0 to 5 are 0
#define SIGN_MODE_INTERNAL              ((uint8_t) 0x00)       //!< Sign mode     0: internal
#define SIGN_MODE_INCLUDE_SN            ((uint8_t) 0x40)       //!< Sign mode bit 6: include serial number
#define SIGN_MODE_EXTERNAL              ((uint8_t) 0x80)       //!< Sign mode bit 7: external
/** @} */

/** \name Definitions for the UpdateExtra Command
@{ */
#define UPDATE_MODE_IDX                  ECC108_PARAM1_IDX     //!< UpdateExtra command index for mode
#define UPDATE_VALUE_IDX                 ECC108_PARAM2_IDX     //!< UpdateExtra command index for new value
#define UPDATE_COUNT                     ECC108_CMD_SIZE_MIN   //!< UpdateExtra command packet size
#define UPDATE_CONFIG_BYTE_85            ((uint8_t) 0x01)      //!< UpdateExtra mode: update Config byte 85
/** @} */

/** \name Definitions for the Verify Command
@{ */
#define VERIFY_MODE_IDX                 ECC108_PARAM1_IDX      //!< Verify command index for mode
#define VERIFY_KEYID_IDX                ECC108_PARAM2_IDX      //!< Verify command index for key id
#define VERIFY_DATA_IDX                 (  5)                  //!< Verify command index for data
#define VERIFY_256_STORED_COUNT         ( 71)                  //!< Verify command packet size for 256-bit key in stored mode
#define VERIFY_283_STORED_COUNT         ( 79)                  //!< Verify command packet size for 283-bit key in stored mode
#define VERIFY_256_VALIDATE_COUNT       ( 90)                  //!< Verify command packet size for 256-bit key in validate mode
#define VERIFY_283_VALIDATE_COUNT       ( 98)                  //!< Verify command packet size for 283-bit key in validate mode
#define VERIFY_256_EXTERNAL_COUNT       (135)                  //!< Verify command packet size for 256-bit key in external mode
#define VERIFY_283_EXTERNAL_COUNT       (151)                  //!< Verify command packet size for 283-bit key in external mode
#define VERIFY_256_KEY_SIZE             ( 64)                  //!< Verify key size for 256-bit key
#define VERIFY_283_KEY_SIZE             ( 72)                  //!< Verify key size for 283-bit key
#define VERIFY_256_SIGNATURE_SIZE       ( 64)                  //!< Verify signature size for 256-bit key
#define VERIFY_283_SIGNATURE_SIZE       ( 72)                  //!< Verify signature size for 283-bit key
#define VERIFY_OTHER_DATA_SIZE          ( 19)                  //!< Verify size of "other data"
#define VERIFY_MODE_MASK                ((uint8_t) 0x03)       //!< Verify mode bits 2 to 7 are 0
#define VERIFY_MODE_STORED              ((uint8_t) 0x00)       //!< Verify mode: stored
#define VERIFY_MODE_EXTERNAL            ((uint8_t) 0x02)       //!< Verify mode: external
#define VERIFY_MODE_VALIDATE            ((uint8_t) 0x03)       //!< Verify mode: validate
#define VERIFY_KEY_B283                 ((uint16_t) 0x0000)    //!< Verify key type: B283
#define VERIFY_KEY_K283                 ((uint16_t) 0x0001)    //!< Verify key type: K283
#define VERIFY_KEY_P256                 ((uint16_t) 0x0004)    //!< Verify key type: P256
/** @} */

/** \name Definitions for the Write Command
@{ */
#define WRITE_ZONE_IDX                  ECC108_PARAM1_IDX      //!< Write command index for zone
#define WRITE_ADDR_IDX                  ECC108_PARAM2_IDX      //!< Write command index for address
#define WRITE_VALUE_IDX                 ECC108_DATA_IDX        //!< Write command index for data
#define WRITE_MAC_VS_IDX                ( 9)                   //!< Write command index for MAC following short data
#define WRITE_MAC_VL_IDX                (37)                   //!< Write command index for MAC following long data
#define WRITE_COUNT_SHORT               (11)                   //!< Write command packet size with short data and no MAC
#define WRITE_COUNT_LONG                (39)                   //!< Write command packet size with long data and no MAC
#define WRITE_COUNT_SHORT_MAC           (43)                   //!< Write command packet size with short data and MAC
#define WRITE_COUNT_LONG_MAC            (71)                   //!< Write command packet size with long data and MAC
#define WRITE_MAC_SIZE                  (32)                   //!< Write MAC size
#define WRITE_ZONE_MASK                 ((uint8_t) 0xC3)       //!< Write zone bits 2 to 5 are 0.
#define WRITE_ZONE_WITH_MAC             ((uint8_t) 0x40)       //!< Write zone bit 6: write encrypted with MAC
#define WRITE_ZONE_OTP                  ((uint8_t) 1)          //!< WRITE zone id OTP
#define WRITE_ZONE_DATA                 ((uint8_t) 2)          //!< WRITE zone id data
/** @} */

/** \name Response Size Definitions
@{ */
#define CHECKMAC_RSP_SIZE               ECC108_RSP_SIZE_MIN    //!< response size of DeriveKey command
#define DERIVE_KEY_RSP_SIZE             ECC108_RSP_SIZE_MIN    //!< response size of DeriveKey command
#define GENDIG_RSP_SIZE                 ECC108_RSP_SIZE_MIN    //!< response size of GenDig command
#define GENKEY_RSP_SIZE_SHORT           ECC108_RSP_SIZE_MIN    //!< response size of GenKey command in Digest mode
#define GENKEY_RSP_SIZE_LONG            ECC108_RSP_SIZE_72     //!< response size of GenKey command when generating key
#define HMAC_RSP_SIZE                   ECC108_RSP_SIZE_MAX    //!< response size of HMAC command
#define INFO_RSP_SIZE                   ECC108_RSP_SIZE_VAL    //!< response size of Info command returns 4 bytes
#define LOCK_RSP_SIZE                   ECC108_RSP_SIZE_MIN    //!< response size of Lock command
#define MAC_RSP_SIZE                    ECC108_RSP_SIZE_32     //!< response size of MAC command
#define NONCE_RSP_SIZE_SHORT            ECC108_RSP_SIZE_MIN    //!< response size of Nonce command with mode[0:1] = 3
#define NONCE_RSP_SIZE_LONG             ECC108_RSP_SIZE_32     //!< response size of Nonce command
#define PAUSE_RSP_SIZE                  ECC108_RSP_SIZE_MIN    //!< response size of Pause command
#define PRIVWRITE_RSP_SIZE              ECC108_RSP_SIZE_MIN    //!< response size of PrivWrite command
#define RANDOM_RSP_SIZE                 ECC108_RSP_SIZE_32     //!< response size of Random command
#define READ_4_RSP_SIZE                 ECC108_RSP_SIZE_VAL    //!< response size of Read command when reading 4 bytes
#define READ_32_RSP_SIZE                ECC108_RSP_SIZE_32     //!< response size of Read command when reading 32 bytes
#define SIGN_RSP_SIZE                   ECC108_RSP_SIZE_MAX    //!< response size of Sign command
#define UPDATE_RSP_SIZE                 ECC108_RSP_SIZE_MIN    //!< response size of UpdateExtra command
#define VERIFY_RSP_SIZE                 ECC108_RSP_SIZE_MIN    //!< response size of UpdateExtra command
#define WRITE_RSP_SIZE                  ECC108_RSP_SIZE_MIN    //!< response size of Write command
/** @} */


/** \name Definitions of Typical Command Execution Times
 * The library starts polling the device for a response after these delays.
@{ */
//! CheckMAC typical command delay
#define CHECKMAC_DELAY                  ((uint8_t) (12.0 * CPU_CLOCK_DEVIATION_NEGATIVE + 0.5))

//! DeriveKey typical command delay
#define DERIVE_KEY_DELAY                ((uint8_t) (14.0 * CPU_CLOCK_DEVIATION_NEGATIVE + 0.5))

//! GenDig typical command delay
#define GENDIG_DELAY                    ((uint8_t) (11.0 * CPU_CLOCK_DEVIATION_NEGATIVE + 0.5))

//! GenKey typical command delay
#define GENKEY_DELAY                    ((uint8_t) (40.0 * CPU_CLOCK_DEVIATION_NEGATIVE + 0.5))

//! HMAC typical command delay
#define HMAC_DELAY                      ((uint8_t) (27.0 * CPU_CLOCK_DEVIATION_NEGATIVE + 0.5))

//! Info typical command delay.
// We set the delay value to 1.0 instead of 0.4 because we have to make sure that we don't poll immediately.
#define INFO_DELAY                      ((uint8_t) ( 1.0 * CPU_CLOCK_DEVIATION_NEGATIVE + 0.5))

//! Lock typical command delay
#define LOCK_DELAY                      ((uint8_t) ( 5.0 * CPU_CLOCK_DEVIATION_NEGATIVE + 0.5))

//! MAC typical command delay
#define MAC_DELAY                       ((uint8_t) (12.0 * CPU_CLOCK_DEVIATION_NEGATIVE + 0.5))

//! Nonce typical command delay
#define NONCE_DELAY                     ((uint8_t) (22.0 * CPU_CLOCK_DEVIATION_NEGATIVE + 0.5))

//! Pause typical command delay
// We set the delay value to 1.0 instead of 0.1 because we have to make sure that we don't poll immediately.
#define PAUSE_DELAY                     ((uint8_t) ( 1.0 * CPU_CLOCK_DEVIATION_NEGATIVE + 0.5))

//! PrivWrite typical command delay
// We set the delay value to 1.0 instead of 0.8 because we have to make sure that we don't poll immediately.
#define PRIVWRITE_DELAY                 ((uint8_t) (12.0 * CPU_CLOCK_DEVIATION_NEGATIVE + 0.5))

//! Random typical command delay
#define RANDOM_DELAY                    ((uint8_t) (11.0 * CPU_CLOCK_DEVIATION_NEGATIVE + 0.5))

//! Read typical command delay
// We set the delay value to 1.0 instead of 0.1 because we have to make sure that we don't poll immediately.
#define READ_DELAY                      ((uint8_t) ( 1.0 * CPU_CLOCK_DEVIATION_NEGATIVE + 0.5))

//! Sign typical command delay
#define SIGN_DELAY                      ((uint8_t) (60.0 * CPU_CLOCK_DEVIATION_NEGATIVE + 0.5))

//! UpdateExtra typical command delay
#define UPDATE_DELAY                    ((uint8_t) ( 4.0 * CPU_CLOCK_DEVIATION_NEGATIVE + 0.5))

//! Verify typical command delay
#define VERIFY_DELAY                    ((uint8_t) (60.0 * CPU_CLOCK_DEVIATION_NEGATIVE + 0.5))

//! Write typical command delay
#define WRITE_DELAY                     ((uint8_t) ( 4.0 * CPU_CLOCK_DEVIATION_NEGATIVE + 0.5))
/** @} */


/** \name Definitions of Maximum Command Execution Times
@{ */
//! CheckMAC maximum execution time
#define CHECKMAC_EXEC_MAX                ((uint8_t) ( 38.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! DeriveKey maximum execution time
#define DERIVE_KEY_EXEC_MAX              ((uint8_t) ( 62.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! GenDig maximum execution time
#define GENDIG_EXEC_MAX                  ((uint8_t) ( 43.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! GenDig maximum execution time
#define GENKEY_EXEC_MAX                  ((uint8_t) (200.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! HMAC maximum execution time
#define HMAC_EXEC_MAX                    ((uint8_t) ( 69.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! Info maximum execution time
#define INFO_EXEC_MAX                    ((uint8_t) (  2.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! Lock maximum execution time
#define LOCK_EXEC_MAX                    ((uint8_t) ( 24.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! MAC maximum execution time
#define MAC_EXEC_MAX                     ((uint8_t) ( 35.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! Nonce maximum execution time
#define NONCE_EXEC_MAX                   ((uint8_t) ( 60.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! Pause maximum execution time
#define PAUSE_EXEC_MAX                   ((uint8_t) (  2.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! PrivWrite maximum execution time
#define PRIVWRITE_EXEC_MAX               ((uint8_t) ( 12.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! Random maximum execution time
#define RANDOM_EXEC_MAX                  ((uint8_t) ( 50.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! Read maximum execution time
#define READ_EXEC_MAX                    ((uint8_t) (  4.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! Sign maximum execution time
#define SIGN_EXEC_MAX                    ((uint8_t) (200.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! UpdateExtra maximum execution time
#define UPDATE_EXEC_MAX                  ((uint8_t) (  6.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! Verify maximum execution time
#define VERIFY_EXEC_MAX                  ((uint8_t) (200.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! Write maximum execution time
#define WRITE_EXEC_MAX                   ((uint8_t) ( 42.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))
/** @} */

uint8_t ecc108m_execute(uint8_t op_code, uint8_t param1, uint16_t param2,
			uint8_t datalen1, uint8_t *data1, uint8_t datalen2, uint8_t *data2, uint8_t datalen3, uint8_t *data3,
			uint8_t tx_size, uint8_t *tx_buffer, uint8_t rx_size, uint8_t *rx_buffer);

/** @} */

#endif
#ifdef __cplusplus
}
#endif
