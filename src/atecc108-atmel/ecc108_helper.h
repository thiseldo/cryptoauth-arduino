#ifdef __cplusplus
extern "C" {
#endif
/** \file
 *  \brief  Definitions and Prototypes for ECC108 Helper Functions
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
 */

#ifndef ECC108_HELPER_H
#   define ECC108_HELPER_H

#include "ecc108_comm_marshaling.h" // definitions and declarations for the Command Marshaling module


/** \defgroup atecc108_helper Module 06: Helper Functions
 *
 * \brief
 * Use these functions if your system does not use an ATECC108 as a host but
 * implements the host in firmware. The functions provide host-side cryptographic functionality
 * for an ATECC108 client device. They are intended to accompany the ATECC108 library functions.
 * They can be called directly from an application, or integrated into an API.
 *
 * Modern compilers can garbage-collect unused functions. If your compiler does not support this feature,
 * you can just discard this module from your project if you do use an ATECC108 as a host. Or, if you don't,
 * delete the functions you do not use.
@{ */

/** \name Definitions for ECC108 Message Sizes to Calculate a SHA256 Hash

 *  \brief "||" is the concatenation operator.
 *         The number in braces is the length of the hash input value in bytes.
@{ */

//! RandOut{32} || NumIn{20} || OpCode{1} || Mode{1} || LSB of Param2{1}
#define ECC108_MSG_SIZE_NONCE            (55)


/** \brief (Key or TempKey){32} || (Challenge or TempKey){32} || OpCode{1} || Mode{1} || Param2{2}
	       || (OTP0_7 or 0){8} || (OTP8_10 or 0){3} || SN8{1} || (SN4_7 or 0){4} || SN0_1{2} || (SN2_3 or 0){2}
*/
#define ECC108_MSG_SIZE_MAC              (88)

/** \brief HMAC = sha(HMAC outer || HMAC inner)
           HMAC inner = sha((zero-padded key ^ ipad) || message)
	                  = sha256(
				          (Key{32} || 0x36{32})
                          || 0{32} || Key{32}
                          || OpCode{1} || Mode{1} || KeyId{2}
                          || OTP0_7{8} || OTP8_10{3} || SN8{1} || SN4_7{4} || SN0_1{2} || SN2_3{2}
                        ){32}
*/
#define ECC108_MSG_SIZE_HMAC_INNER      (152)


/** \brief HMAC = sha(HMAC outer || HMAC inner)
                = sha256((Key{32} || 0x5C{32}) || HMAC inner{32})
*/
#define ECC108_MSG_SIZE_HMAC             (96)


//! KeyId{32} || OpCode{1} || Param1{1} || Param2{2} || SN8{1} || SN0_1{2} || 0{25} || TempKey{32}
#define ECC108_MSG_SIZE_GEN_DIG          (96)


//! KeyId{32} || OpCode{1} || Param1{1} || Param2{2} || SN8{1} || SN0_1{2} || 0{25} || TempKey{32}
#define ECC108_MSG_SIZE_DERIVE_KEY       (96)


//! KeyId{32} || OpCode{1} || Param1{1} || Param2{2} || SN8{1} || SN0_1{2}
#define ECC108_MSG_SIZE_DERIVE_KEY_MAC   (39)

//! KeyId{32} || OpCode{1} || Param1{1} || Param2{2}|| SN8{1} || SN0_1{2} || 0{25} || TempKey{32}
#define ECC108_MSG_SIZE_ENCRYPT_MAC      (96)


#define ECC108_COMMAND_HEADER_SIZE       ( 4)
#define ECC108_GENDIG_ZEROS_SIZE         (25)
#define ECC108_DERIVE_KEY_ZEROS_SIZE     (25)
#define ECC108_OTP_SIZE_8                ( 8)
#define ECC108_OTP_SIZE_3                ( 3)
#define ECC108_SN_SIZE_4                 ( 4)
#define ECC108_SN_SIZE_2                 ( 2)
#define ECC108_OTHER_DATA_SIZE_2         ( 2)
#define ECC108_OTHER_DATA_SIZE_3         ( 3)
#define ECC108_OTHER_DATA_SIZE_4         ( 4)
#define HMAC_BLOCK_SIZE                  (64)
#define ECC108_PACKET_OVERHEAD           ( 3)
/** @} */

/** \name Fixed Byte Values of Serial Number (SN[0:1] and SN[8])
@{ */
#define ECC108_SN_0                    (0x01)
#define ECC108_SN_1                    (0x23)
#define ECC108_SN_8                    (0xEE)
/** @} */


/** \name Definition for TempKey Mode
@{ */
//! mode mask for MAC command when using TempKey
#define MAC_MODE_USE_TEMPKEY_MASK      ((uint8_t) 0x03)
/** @} */

/** \struct ecc108h_temp_key
 *  \brief Structure to hold TempKey fields
 *  \var ecc108h_temp_key::value
 *       \brief The value of TempKey. Nonce (from nonce command) or Digest (from GenDig command)
 *  \var ecc108h_temp_key::key_id
 *       \brief If TempKey was generated by GenDig (see the GenData and CheckFlag bits), these bits indicate which key was used in its computation.
 *  \var ecc108h_temp_key::source_flag
 *       \brief The source of the randomness in TempKey: 0=Rand, 1=Input.
 *  \var ecc108h_temp_key::gen_data
 *       \brief Indicates if TempKey has been generated by GenDig using Data zone.
 *  \var ecc108h_temp_key::check_flag
 *       \brief Not used in the library.
 *  \var ecc108h_temp_key::valid
 *       \brief Indicates if the information in TempKey is valid.
 */
struct ecc108h_temp_key {
	uint8_t value[ECC108_KEY_SIZE];
	unsigned int key_id      : 4;
	unsigned int source_flag : 1;
	unsigned int gen_data    : 1;
	unsigned int check_flag  : 1;
	unsigned int valid       : 1;
};


/** \struct ecc108h_include_data_in_out
 *  \brief Input / output parameters for function ecc108h_include_data().
 *  \var ecc108h_include_data_in_out::p_temp
 *       \brief [out] pointer to output buffer
 *  \var ecc108h_include_data_in_out::otp
 *       \brief [in] pointer to one-time-programming data
 *  \var ecc108h_include_data_in_out::sn
 *       \brief [out] pointer to serial number data
 */
struct ecc108h_include_data_in_out {
	uint8_t *p_temp;
	uint8_t *otp;
	uint8_t *sn;
	uint8_t mode;
};


/** \struct ecc108h_calculate_sha256_in_out
 *  \brief Input/output parameters for function ecc108h_nonce().
 *  \var ecc108h_calculate_sha256_in_out::length
 *       \brief [in] Length of input message to be digested.
 *  \var ecc108h_calculate_sha256_in_out::message
 *       \brief [in] Pointer to input message.
 *  \var ecc108h_calculate_sha256_in_out::digest
 *       \brief [out] Pointer to 32-byte SHA256 digest of input message.
 */
struct ecc108h_calculate_sha256_in_out {
	uint32_t length;
	uint8_t *message;
	uint8_t *digest;
};


/** \struct ecc108h_nonce_in_out
 *  \brief Input/output parameters for function ecc108h_nonce().
 *  \var ecc108h_nonce_in_out::mode
 *       \brief [in] Mode parameter used in Nonce command (Param1).
 *  \var ecc108h_nonce_in_out::num_in
 *       \brief [in] Pointer to 20-byte NumIn data used in Nonce command.
 *  \var ecc108h_nonce_in_out::rand_out
 *       \brief [in] Pointer to 32-byte RandOut data from Nonce command.
 *  \var ecc108h_nonce_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct ecc108h_nonce_in_out {
	uint8_t mode;
	uint8_t *num_in;
	uint8_t *rand_out;
	struct ecc108h_temp_key *temp_key;
};


/** \struct ecc108h_mac_in_out
 *  \brief Input/output parameters for function ecc108h_mac().
 *  \var ecc108h_mac_in_out::mode
 *       \brief [in] Mode parameter used in MAC command (Param1).
 *  \var ecc108h_mac_in_out::key_id
 *       \brief [in] KeyID parameter used in MAC command (Param2).
 *  \var ecc108h_mac_in_out::challenge
 *       \brief [in] Pointer to 32-byte Challenge data used in MAC command, depending on mode.
 *  \var ecc108h_mac_in_out::key
 *       \brief [in] Pointer to 32-byte key used to generate MAC digest.
 *  \var ecc108h_mac_in_out::otp
 *       \brief [in] Pointer to 11-byte OTP, optionally included in MAC digest, depending on mode.
 *  \var ecc108h_mac_in_out::sn
 *       \brief [in] Pointer to 9-byte SN, optionally included in MAC digest, depending on mode.
 *  \var ecc108h_mac_in_out::response
 *       \brief [out] Pointer to 32-byte SHA-256 digest (MAC).
 *  \var ecc108h_mac_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct ecc108h_mac_in_out {
	uint8_t mode;
	uint16_t key_id;
	uint8_t *challenge;
	uint8_t *key;
	uint8_t *otp;
	uint8_t *sn;
	uint8_t *response;
	struct ecc108h_temp_key *temp_key;
};


/** \struct ecc108h_hmac_in_out
 *  \brief Input/output parameters for function ecc108h_hmac().
 *  \var ecc108h_hmac_in_out::mode
 *       \brief [in] Mode parameter used in HMAC command (Param1).
 *  \var ecc108h_hmac_in_out::key_id
 *       \brief [in] KeyID parameter used in HMAC command (Param2).
 *  \var ecc108h_hmac_in_out::key
 *       \brief [in] Pointer to 32-byte key used to generate HMAC digest.
 *  \var ecc108h_hmac_in_out::otp
 *       \brief [in] Pointer to 11-byte OTP, optionally included in HMAC digest, depending on mode.
 *  \var ecc108h_hmac_in_out::sn
 *       \brief [in] Pointer to 9-byte SN, optionally included in HMAC digest, depending on mode.
 *  \var ecc108h_hmac_in_out::response
 *       \brief [out] Pointer to 32-byte SHA-256 HMAC digest.
 *  \var ecc108h_hmac_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct ecc108h_hmac_in_out {
	uint8_t mode;
	uint16_t key_id;
	uint8_t *key;
	uint8_t *otp;
	uint8_t *sn;
	uint8_t *response;
	struct ecc108h_temp_key *temp_key;
};


/** \struct ecc108h_gen_dig_in_out
 *  \brief Input/output parameters for function ecc108h_gen_dig().
 *  \var ecc108h_gen_dig_in_out::zone
 *       \brief [in] Zone parameter used in GenDig command (Param1).
 *  \var ecc108h_gen_dig_in_out::key_id
 *       \brief [in] KeyID parameter used in GenDig command (Param2).
 *  \var ecc108h_gen_dig_in_out::stored_value
 *       \brief [in] Pointer to 32-byte stored value, can be a data slot, OTP page, configuration zone, or hardware transport key.
 *  \var ecc108h_gen_dig_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct ecc108h_gen_dig_in_out {
	uint8_t zone;
	uint16_t key_id;
	uint8_t *stored_value;
	struct ecc108h_temp_key *temp_key;
};


/** \struct ecc108h_derive_key_in_out
 *  \brief Input/output parameters for function ecc108h_derive_key().
 *  \var ecc108h_derive_key_in_out::random
 *       \brief [in] Random parameter used in DeriveKey command (Param1).
 *  \var ecc108h_derive_key_in_out::target_key_id
 *       \brief [in] KeyID to be derived, TargetKey parameter used in DeriveKey command (Param2).
 *  \var ecc108h_derive_key_in_out::parent_key
 *       \brief [in] Pointer to 32-byte ParentKey. Set equal to target_key if Roll Key operation is intended.
 *  \var ecc108h_derive_key_in_out::target_key
 *       \brief [out] Pointer to 32-byte TargetKey.
 *  \var ecc108h_derive_key_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct ecc108h_derive_key_in_out {
	uint8_t random;
	uint16_t target_key_id;
	uint8_t *parent_key;
	uint8_t *target_key;
	struct ecc108h_temp_key *temp_key;
};


/** \struct ecc108h_derive_key_mac_in_out
 *  \brief Input/output parameters for function ecc108h_derive_key_mac().
 *  \var ecc108h_derive_key_mac_in_out::random
 *       \brief [in] Random parameter used in DeriveKey command (Param1).
 *  \var ecc108h_derive_key_mac_in_out::target_key_id
 *       \brief [in] KeyID to be derived, TargetKey parameter used in DeriveKey command (Param2).
 *  \var ecc108h_derive_key_mac_in_out::parent_key
 *       \brief [in] Pointer to 32-byte ParentKey. ParentKey here is always SlotConfig[TargetKey].WriteKey, regardless whether the operation is Roll or Create.
 *  \var ecc108h_derive_key_mac_in_out::mac
 *       \brief [out] Pointer to 32-byte Mac.
 */
struct ecc108h_derive_key_mac_in_out {
	uint8_t random;
	uint16_t target_key_id;
	uint8_t *parent_key;
	uint8_t *mac;
};


/** \struct ecc108h_encrypt_in_out
 *  \brief Input/output parameters for function ecc108h_encrypt().
 *  \var ecc108h_encrypt_in_out::zone
 *       \brief [in] Zone parameter used in Write (Param1).
 *  \var ecc108h_encrypt_in_out::address
 *       \brief [in] Address parameter used in Write command (Param2).
 *  \var ecc108h_encrypt_in_out::crypto_data
 *       \brief [in,out] Pointer to 32-byte data. Input cleartext data, output encrypted data to Write command (Value field).
 *  \var ecc108h_encrypt_in_out::mac
 *       \brief [out] Pointer to 32-byte Mac. Can be set to NULL if input MAC is not required by the Write command (write to OTP, unlocked user zone).
 *  \var ecc108h_encrypt_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct ecc108h_encrypt_in_out {
	uint8_t zone;
	uint16_t address;
	uint8_t *crypto_data;
	uint8_t *mac;
	struct ecc108h_temp_key *temp_key;
};


/** \struct ecc108h_decrypt_in_out
 *  \brief Input/output parameters for function ecc108h_decrypt().
 *  \var ecc108h_decrypt_in_out::crypto_data
 *       \brief [in,out] Pointer to 32-byte data. Input encrypted data from Read command (Contents field), output decrypted.
 *  \var ecc108h_decrypt_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct ecc108h_decrypt_in_out {
	uint8_t *crypto_data;
	struct ecc108h_temp_key *temp_key;
};


/** \struct ecc108h_check_mac_in_out
 *  \brief Input/output parameters for function ecc108h_check_mac().
 *  \var ecc108h_check_mac_in_out::mode
 *       \brief [in] Mode parameter used in CheckMac command (Param1).
 *  \var ecc108h_check_mac_in_out::password
 *       \brief [in] Pointer to 32-byte password that will be verified against Key[KeyID] in the Device.
 *  \var ecc108h_check_mac_in_out::other_data
 *       \brief [in] Pointer to 13-byte OtherData that will be used in CheckMac command.
 *  \var ecc108h_check_mac_in_out::otp
 *       \brief [in] Pointer to 11-byte OTP. OTP[0:7] is included in the calculation if Mode bit 5 is one.
 *  \var ecc108h_check_mac_in_out::target_key
 *       \brief [in] Pointer to 32-byte TargetKey that will be copied to TempKey.
 *  \var ecc108h_check_mac_in_out::client_resp
 *       \brief [out] Pointer to 32-byte ClientResp to be used in CheckMac command.
 *  \var ecc108h_check_mac_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct ecc108h_check_mac_in_out {
	uint8_t mode;
	uint8_t *password;
	uint8_t *other_data;
	uint8_t *otp;
	uint8_t *target_key;
	uint8_t *client_resp;
	struct ecc108h_temp_key *temp_key;
};


/** \struct ecc108h_verify_in_out
 *  \brief Input/output parameters for function ecc108h_verify().
 *  \var ecc108h_verify_in_out::curve_type
 *       \brief [in] Curve type used in Verify command (Param2).
 *  \var ecc108h_decrypt_in_out::signature
 *       \brief [in] Pointer to ECDSA signature to be verified
 *  \var ecc108h_decrypt_in_out::public_key
 *       \brief [in] Pointer to the public key to be used for verification
 *  \var ecc108h_decrypt_in_out::temp_key
 *       \brief [in,out] Pointer to TempKey structure.
 */
struct ecc108h_verify_in_out {
	uint16_t curve_type;
	uint8_t *signature;
	uint8_t *public_key;
	struct ecc108h_temp_key *temp_key;
};


char   *ecc108h_get_library_version(void);
uint8_t ecc108h_nonce(struct ecc108h_nonce_in_out *param);
uint8_t ecc108h_mac(struct ecc108h_mac_in_out *param);
uint8_t ecc108h_check_mac(struct ecc108h_check_mac_in_out *param);
uint8_t ecc108h_hmac(struct ecc108h_hmac_in_out *param);
uint8_t ecc108h_gen_dig(struct ecc108h_gen_dig_in_out *param);
uint8_t ecc108h_derive_key(struct ecc108h_derive_key_in_out *param);
uint8_t ecc108h_derive_key_mac(struct ecc108h_derive_key_mac_in_out *param);
uint8_t ecc108h_encrypt(struct ecc108h_encrypt_in_out *param);
uint8_t ecc108h_decrypt(struct ecc108h_decrypt_in_out *param);
void ecc108h_calculate_crc_chain(uint8_t length, uint8_t *data, uint8_t *crc);
void ecc108h_calculate_sha256(int32_t len, uint8_t *message, uint8_t *digest);
uint8_t ecc108h_verify(struct ecc108h_verify_in_out *param);
uint8_t *ecc108h_include_data(struct ecc108h_include_data_in_out *param);

/** @} */

#endif //ECC108_HELPER_H
#ifdef __cplusplus
}
#endif
