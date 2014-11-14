/** \file
 *  \brief  ATSHA204 Helper Functions
 *  \author Atmel Crypto Products
 *  \date   January 15, 2013

 * \copyright Copyright (c) 2013 Atmel Corporation. All rights reserved.
 *
 * \atsha204_library_license_start
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
 * \atsha204_library_license_stop
 */

#include <string.h>                    // needed for memcpy()
#include <stdint.h>

#include "sha204_helper.h"             // header module for this C module
#include "sha204_lib_return_codes.h"   // declarations of function return codes
#include "sha204_comm_marshaling.h"    // definitions and declarations for the Command Marshaling module


/** \brief This function returns the library version.
 *         The version consists of three bytes. For a released version, the last byte is 0.
 *
 *  \return pointer to the version string
 */
char *sha204h_get_library_version(void)
{
	static char *version= "\x2\x0\x0";
	return version;
}


/** \brief This function copies otp and sn data into a command buffer.
 *
 * \param[in, out] param pointer to parameter structure
 * \return pointer to command buffer byte that was copied last
 */
uint8_t *sha204h_include_data(struct sha204h_include_data_in_out *param)
{
	if (param->mode & MAC_MODE_INCLUDE_OTP_88) {
		memcpy(param->p_temp, param->otp, SHA204_OTP_SIZE_8 + SHA204_OTP_SIZE_3);            // use OTP[0:10], Mode:5 is overridden
		param->p_temp += SHA204_OTP_SIZE_8 + SHA204_OTP_SIZE_3;
	}
	else {
		if (param->mode & MAC_MODE_INCLUDE_OTP_64)
			memcpy(param->p_temp, param->otp, SHA204_OTP_SIZE_8);        // use 8 bytes OTP[0:7] for (6)
		else
			memset(param->p_temp, 0, SHA204_OTP_SIZE_8);                 // use 8 zeros for (6)
		param->p_temp += SHA204_OTP_SIZE_8;

		memset(param->p_temp, 0, SHA204_OTP_SIZE_3);                     // use 3 zeros for (7)
		param->p_temp += SHA204_OTP_SIZE_3;
	}

	// (8) 1 byte SN[8] = 0xEE
	*param->p_temp++ = SHA204_SN_8;

	// (9) 4 bytes SN[4:7] or zeros
	if (param->mode & MAC_MODE_INCLUDE_SN)
		memcpy(param->p_temp, &param->sn[4], SHA204_SN_SIZE_4);          //use SN[4:7] for (9)
	else
		memset(param->p_temp, 0, SHA204_SN_SIZE_4);                      //use zeros for (9)
	param->p_temp += SHA204_SN_SIZE_4;

	// (10) 2 bytes SN[0:1] = 0x0123
	*param->p_temp++ = SHA204_SN_0;
	*param->p_temp++ = SHA204_SN_1;

	// (11) 2 bytes SN[2:3] or zeros
	if (param->mode & MAC_MODE_INCLUDE_SN)
		memcpy(param->p_temp, &param->sn[2], SHA204_SN_SIZE_2);          //use SN[2:3] for (11)
	else
		memset(param->p_temp, 0, SHA204_SN_SIZE_2);                      //use zeros for (9)
	param->p_temp += SHA204_SN_SIZE_2;
	
	return param->p_temp;
}


/** \brief This function calculates a 32-byte nonce based on a 20-byte input value (param->num_in) and 32-byte random number (param->rand_out).
 
This nonce will match with the nonce generated in the device when executing a Nonce command.
To use this function, an application first sends a Nonce command with a chosen param->num_in to the device.
Nonce Mode parameter must be set to use random nonce (mode 0 or 1).\n
The device generates a nonce, stores it in its TempKey, and outputs the random number param->rand_out it used in the hash calculation to the host.
The values of param->rand_out and param->num_in are passed to this nonce calculation function. The function calculates the nonce and returns it.
This function can also be used to fill in the nonce directly to TempKey (pass-through mode). The flags will automatically be set according to the mode used.
    \param[in, out] param pointer to parameter structure
    \return status of the operation
 */
uint8_t sha204h_nonce(struct sha204h_nonce_in_out *param)
{
	uint8_t temporary[SHA204_MSG_SIZE_NONCE];
	uint8_t *p_temp;

	// Check parameters
	if (!param->temp_key || !param->num_in || (param->mode > NONCE_MODE_PASSTHROUGH) || (param->mode == NONCE_MODE_INVALID)
			|| (((param->mode == NONCE_MODE_SEED_UPDATE || (param->mode == NONCE_MODE_NO_SEED_UPDATE)) && !param->rand_out)))
		return SHA204_BAD_PARAM;

	// Calculate or pass-through the nonce to TempKey->Value
	if ((param->mode == NONCE_MODE_SEED_UPDATE) || (param->mode == NONCE_MODE_NO_SEED_UPDATE)) {
		// Calculate nonce using SHA-256 (refer to data sheet)
		p_temp = temporary;

		memcpy(p_temp, param->rand_out, NONCE_RSP_SIZE_LONG - SHA204_PACKET_OVERHEAD);
		p_temp += NONCE_RSP_SIZE_LONG - SHA204_PACKET_OVERHEAD;

		memcpy(p_temp, param->num_in, NONCE_NUMIN_SIZE);
		p_temp += NONCE_NUMIN_SIZE;

		*p_temp++ = SHA204_NONCE;
		*p_temp++ = param->mode;
		*p_temp++ = 0x00;

		// Calculate SHA256 to get the nonce
		sha204h_calculate_sha256(SHA204_MSG_SIZE_NONCE, temporary, param->temp_key->value);

		// Update TempKey->SourceFlag to 0 (random)
		param->temp_key->source_flag = 0;
	} 
	else if (param->mode == NONCE_MODE_PASSTHROUGH) {
		// Pass-through mode
		memcpy(param->temp_key->value, param->num_in, NONCE_NUMIN_SIZE_PASSTHROUGH);

		// Update TempKey->SourceFlag to 1 (not random)
		param->temp_key->source_flag = 1;
	}

	// Update TempKey fields
	param->temp_key->key_id = 0;
	param->temp_key->gen_data = 0;
	param->temp_key->check_flag = 0;
	param->temp_key->valid = 1;

	return SHA204_SUCCESS;
}


/** \brief This function generates an SHA-256 digest (MAC) of a key, challenge, and other information.
 
The resulting digest will match with the one generated by the device when executing a MAC command.
The TempKey (if used) should be valid (temp_key.valid = 1) before executing this function.
 
 * \param[in, out] param pointer to parameter structure
 * \return status of the operation
 */
uint8_t sha204h_mac(struct sha204h_mac_in_out *param)
{
	uint8_t temporary[SHA204_MSG_SIZE_MAC];
	uint8_t *p_temp;
	struct sha204h_include_data_in_out include_data = {
		.otp = param->otp, .sn = param->sn, .mode = param->mode
	};
	
	// Check parameters
	if (!param->response
		|| (param->mode & ~MAC_MODE_MASK)
		|| (!(param->mode & MAC_MODE_BLOCK1_TEMPKEY) && !param->key)
		|| (!(param->mode & MAC_MODE_BLOCK2_TEMPKEY) && !param->challenge)
		|| ((param->mode & MAC_MODE_USE_TEMPKEY_MASK) && !param->temp_key)
		|| (((param->mode & MAC_MODE_INCLUDE_OTP_64) || (param->mode & MAC_MODE_INCLUDE_OTP_88)) && !param->otp)
		|| ((param->mode & MAC_MODE_INCLUDE_SN) && !param->sn)
		)
		return SHA204_BAD_PARAM;

	// Check TempKey fields validity if TempKey is used
	if (((param->mode & MAC_MODE_USE_TEMPKEY_MASK) != 0)
			// TempKey.CheckFlag must be 0 and TempKey.Valid must be 1
			&& (param->temp_key->check_flag || (param->temp_key->valid != 1)
			// If either mode parameter bit 0 or bit 1 are set, mode parameter bit 2 must match temp_key.source_flag.
			// Logical not (!) is used to evaluate the expression to TRUE / FALSE first before comparison (!=).
			|| (!(param->mode & MAC_MODE_SOURCE_FLAG_MATCH) != !(param->temp_key->source_flag)))
		)
	{
		// Invalidate TempKey, then return
		param->temp_key->valid = 0;
		return SHA204_CMD_FAIL;
	}

	// Start calculation
	p_temp = temporary;

	// (1) first 32 bytes
	memcpy(p_temp, param->mode & MAC_MODE_BLOCK1_TEMPKEY ? param->temp_key->value : param->key, SHA204_KEY_SIZE);                // use Key[KeyID]
	p_temp += SHA204_KEY_SIZE;

	// (2) second 32 bytes
	memcpy(p_temp, param->mode & MAC_MODE_BLOCK2_TEMPKEY ? param->temp_key->value : param->challenge, SHA204_KEY_SIZE);          // use Key[KeyID]
	p_temp += SHA204_KEY_SIZE;

	// (3) 1 byte opcode
	*p_temp++ = SHA204_MAC;

	// (4) 1 byte mode parameter
	*p_temp++ = param->mode;

	// (5) 2 bytes keyID
	*p_temp++ = param->key_id & 0xFF;
	*p_temp++ = (param->key_id >> 8) & 0xFF;
	
	include_data.p_temp = p_temp;
	sha204h_include_data(&include_data);

	// Calculate SHA256 to get the MAC digest
	sha204h_calculate_sha256(SHA204_MSG_SIZE_MAC, temporary, param->response);

	// Update TempKey fields
	if (param->temp_key)
		param->temp_key->valid = 0;

	return SHA204_SUCCESS;
}


/** \brief This function calculates a SHA-256 digest (MAC) of a password and other information, to be verified using the CheckMac device command.
 
This password checking operation is described in "Section 3.3.6 Password Checking" of "Atmel ATSHA204 [DATASHEET]" (8740C-CRYPTO-7/11).
Before performing password checking operation, TempKey should contain a randomly generated nonce. The TempKey in the device has to match the one in the application.
A user enters the password to be verified by an application.
The application passes this password to the CheckMac calculation function, along with 13 bytes of OtherData, a 32-byte target key, and optionally 11 bytes of OTP.
The function calculates a 32-byte ClientResp, returns it to Application. The function also replaces the current TempKey value with the target key.
The application passes the calculated ClientResp along with OtherData inside a CheckMac command to the device.
The device validates ClientResp, and copies the target slot to its TempKey.

If the password is stored in an odd numbered slot, the target slot is the password slot itself, so the target_key parameter should point to the password being checked.
If the password is stored in an even numbered slot, the target slot is the next odd numbered slot (KeyID + 1), so the target_key parameter should point to a key that
is equal to the target slot in the device.

Note that the function does not check the result of the password checking operation.
Regardless of whether the CheckMac command returns success or not, the TempKey variable of the application will hold the value of the target key.
Therefore the application has to make sure that password checking operation succeeds before using the TempKey for subsequent operations.
 
 * \param[in, out] param pointer to parameter structure
 * \return status of the operation
 */
uint8_t sha204h_check_mac(struct sha204h_check_mac_in_out *param)
{
	uint8_t temporary[SHA204_MSG_SIZE_MAC];
	uint8_t *p_temp;

	// Check parameters
	if (((param->mode & MAC_MODE_USE_TEMPKEY_MASK) != MAC_MODE_BLOCK2_TEMPKEY)
			|| !param->password || !param->other_data
			|| !param->target_key || !param->client_resp || !param->temp_key
			|| ((param->mode & MAC_MODE_INCLUDE_OTP_64) && !param->otp) 
		)
		return SHA204_BAD_PARAM;

	// Check TempKey fields validity (TempKey is always used.)
	// TempKey.CheckFlag must be 0, TempKey.Valid must be 1, TempKey.SourceFlag must be 0
	if (param->temp_key->check_flag	|| (param->temp_key->valid != 1) || param->temp_key->source_flag)
	{
		// Invalidate TempKey, then return
		param->temp_key->valid = 0;
		return SHA204_CMD_FAIL;
	}

	// Start calculation
	p_temp = temporary;

	// (1) first 32 bytes
	memcpy(p_temp, param->password, SHA204_KEY_SIZE);           // password to be checked
	p_temp += SHA204_KEY_SIZE;

	// (2) second 32 bytes
	memcpy(p_temp, param->temp_key->value, SHA204_KEY_SIZE);    // use TempKey.Value
	p_temp += SHA204_KEY_SIZE;

	// (3, 4, 5) 4 byte OtherData[0:3]
	memcpy(p_temp, &param->other_data[0], SHA204_OTHER_DATA_SIZE_4);
	p_temp += SHA204_OTHER_DATA_SIZE_4;

	// (6) 8 bytes OTP[0:7] or 0x00's
	if (param->mode & MAC_MODE_INCLUDE_OTP_64)
		memcpy(p_temp, param->otp, SHA204_OTP_SIZE_8);         // use 8 bytes OTP[0:7] for (6)
	else
		memset(p_temp, 0, SHA204_OTP_SIZE_8);         // use 8 zeros for (6)
	p_temp += SHA204_OTP_SIZE_8;

	// (7) 3 byte OtherData[4:6]
	memcpy(p_temp, &param->other_data[SHA204_OTHER_DATA_SIZE_4], SHA204_OTHER_DATA_SIZE_3);  // use OtherData[4:6] for (7)
	p_temp += SHA204_OTHER_DATA_SIZE_3;

	// (8) 1 byte SN[8] = 0xEE
	*p_temp++ = SHA204_SN_8;

	// (9) 4 byte OtherData[7:10]
	memcpy(p_temp, &param->other_data[SHA204_OTHER_DATA_SIZE_4 + SHA204_OTHER_DATA_SIZE_3], SHA204_OTHER_DATA_SIZE_4);  // use OtherData[7:10] for (9)
	p_temp += SHA204_OTHER_DATA_SIZE_4;

	// (10) 2 bytes SN[0:1] = 0x0123
	*p_temp++ = SHA204_SN_0;
	*p_temp++ = SHA204_SN_1;

	// (11) 2 byte OtherData[11:12]
	memcpy(p_temp, &param->other_data[SHA204_OTHER_DATA_SIZE_4 + SHA204_OTHER_DATA_SIZE_3 + SHA204_OTHER_DATA_SIZE_2], 
			SHA204_OTHER_DATA_SIZE_2); // use OtherData[11:12] for (11)
	p_temp += SHA204_OTHER_DATA_SIZE_2;

	// Calculate SHA256 to get the MAC digest
	sha204h_calculate_sha256(SHA204_MSG_SIZE_MAC, temporary, param->client_resp);

	// Update TempKey fields
	memcpy(param->temp_key->value, param->target_key, SHA204_KEY_SIZE);
	param->temp_key->gen_data = 0;
	param->temp_key->source_flag = 1;
	param->temp_key->valid = 1;

	return SHA204_SUCCESS;
}


/** \brief This function generates an HMAC / SHA-256 hash of a key and other information.
 
The resulting hash will match with the one generated in the device by an HMAC command.
The TempKey has to be valid (temp_key.valid = 1) before executing this function.
 
 * \param[in, out] param pointer to parameter structure
 * \return status of the operation
 */
uint8_t sha204h_hmac(struct sha204h_hmac_in_out *param)
{
	// Local Variables
	struct sha204h_include_data_in_out include_data = {
		.otp = param->otp, .sn = param->sn, .mode = param->mode
	};
	uint8_t temporary[SHA204_MSG_SIZE_HMAC_INNER];
	uint8_t i;
	uint8_t *p_temp;

	// Check parameters
	if (!param->response || !param->key || !param->temp_key
		|| (param->mode & ~HMAC_MODE_MASK)
		|| (((param->mode & MAC_MODE_INCLUDE_OTP_64) || (param->mode & MAC_MODE_INCLUDE_OTP_88)) && !param->otp)
		|| ((param->mode & MAC_MODE_INCLUDE_SN) && !param->sn) 
		)
		return SHA204_BAD_PARAM;

	// Check TempKey fields validity (TempKey is always used.)
	if (// TempKey.CheckFlag must be 0 and TempKey.Valid must be 1
		   param->temp_key->check_flag || (param->temp_key->valid != 1)
			// The mode parameter bit 2 must match temp_key.source_flag.
			// Logical not (!) is used to evaluate the expression to TRUE / FALSE first before comparison (!=).
			|| (!(param->mode & MAC_MODE_SOURCE_FLAG_MATCH) != !(param->temp_key->source_flag)) 
		)
	{
		// Invalidate TempKey, then return
		param->temp_key->valid = 0;
		return SHA204_CMD_FAIL;
	}

	// Start first calculation (inner)
	p_temp = temporary;

	// Refer to fips-198a.pdf, length Key = 32 bytes, Block size = 512 bits = 64 bytes.
	// So the Key must be padded with zeros.
	// XOR K0 with ipad, then append
	for (i = 0; i < SHA204_KEY_SIZE; i++)
		*p_temp++ = param->key[i] ^ 0x36;

	// XOR the remaining zeros and append
	for (i = 0; i < HMAC_BLOCK_SIZE - SHA204_KEY_SIZE; i++)
		*p_temp++ = 0 ^ 0x36;

	// Next append the stream of data 'text'
	// (1) first 32 bytes: zeros
	memset(p_temp, 0, HMAC_BLOCK_SIZE - SHA204_KEY_SIZE);
	p_temp += HMAC_BLOCK_SIZE - SHA204_KEY_SIZE;

	// (2) second 32 bytes: TempKey
	memcpy(p_temp, param->temp_key->value, SHA204_KEY_SIZE);
	p_temp += SHA204_KEY_SIZE;

	// (3) 1 byte opcode
	*p_temp++ = SHA204_HMAC;

	// (4) 1 byte mode parameter
	*p_temp++ = param->mode;

	// (5) 2 bytes keyID
	*p_temp++ = param->key_id & 0xFF;
	*p_temp++ = (param->key_id >> 8) & 0xFF;

	// Calculate SHA256
	// H((K0^ipad):text), use param.response for temporary storage
	sha204h_calculate_sha256(SHA204_MSG_SIZE_HMAC_INNER, temporary, param->response);

	// Start second calculation (outer)
	p_temp = temporary;

	// XOR K0 with opad, then append
	for (i = 0; i < SHA204_KEY_SIZE; i++) {
		*p_temp++ = param->key[i] ^ 0x5C;
	}

	// XOR the remaining zeros and append
	for (i = 0; i < HMAC_BLOCK_SIZE - SHA204_KEY_SIZE; i++) {
		*p_temp++ = 0 ^ 0x5C;
	}

	// Append result from last calculation H((K0 ^ ipad): text)
	memcpy(p_temp, param->response, SHA204_KEY_SIZE);
	p_temp += SHA204_KEY_SIZE;
	
	include_data.p_temp = p_temp;
	sha204h_include_data(&include_data);

	// Calculate SHA256 to get the resulting HMAC
	sha204h_calculate_sha256(SHA204_MSG_SIZE_HMAC, temporary, param->response);

	// Update TempKey fields
	param->temp_key->valid = 0;

	return SHA204_SUCCESS;
}


/** \brief This function combines the current TempKey with a stored value.
 
The stored value can be a data slot, OTP page, configuration zone, or hardware transport key.
The TempKey generated by this function will match with the TempKey in the device generated
when executing a GenDig command.
The TempKey should be valid (temp_key.valid = 1) before executing this function.
To use this function, an application first sends a GenDig command with a chosen stored value to the device.
This stored value must be known by the application and is passed to this GenDig calculation function.
The function calculates a new TempKey and returns it.
 
 * \param[in, out] param pointer to parameter structure
 * \return status of the operation
 */
uint8_t sha204h_gen_dig(struct sha204h_gen_dig_in_out *param)
{
	uint8_t temporary[SHA204_MSG_SIZE_GEN_DIG];
	uint8_t *p_temp;

	// Check parameters
	if (!param->stored_value || !param->temp_key
			|| ((param->zone != GENDIG_ZONE_OTP) 
				&& (param->zone != GENDIG_ZONE_DATA)
				&& (param->zone != GENDIG_ZONE_CONFIG)) 
		)
		return SHA204_BAD_PARAM;

	// Check TempKey fields validity (TempKey is always used)
	if (// TempKey.CheckFlag must be 0 and TempKey.Valid must be 1
		param->temp_key->check_flag	|| (param->temp_key->valid != 1)
		)
	{
		// Invalidate TempKey, then return
		param->temp_key->valid = 0;
		return SHA204_CMD_FAIL;
	}

	// Start calculation
	p_temp = temporary;

	// (1) 32 bytes inputKey
	//     (Config[KeyID] or OTP[KeyID] or Data.slot[KeyID] or TransportKey[KeyID])
	memcpy(p_temp, param->stored_value, SHA204_KEY_SIZE);
	p_temp += SHA204_KEY_SIZE;

	// (2) 1 byte Opcode
	*p_temp++ = SHA204_GENDIG;

	// (3) 1 byte Param1 (zone)
	*p_temp++ = param->zone;

	// (4) 2 bytes Param2 (keyID)
	*p_temp++ = param->key_id & 0xFF;
	*p_temp++ = (param->key_id >> 8) & 0xFF;

	// (5) 1 byte SN[8] = 0xEE
	*p_temp++ = SHA204_SN_8;

	// (6) 2 bytes SN[0:1] = 0x0123
	*p_temp++ = SHA204_SN_0;
	*p_temp++ = SHA204_SN_1;

	// (7) 25 zeros
	memset(p_temp, 0, SHA204_GENDIG_ZEROS_SIZE);
	p_temp += SHA204_GENDIG_ZEROS_SIZE;

	// (8) 32 bytes TempKey
	memcpy(p_temp, param->temp_key->value, SHA204_KEY_SIZE);

	// Calculate SHA256 to get the new TempKey
	sha204h_calculate_sha256(SHA204_MSG_SIZE_GEN_DIG, temporary, param->temp_key->value);

	// Update TempKey fields
	param->temp_key->valid = 1;

	if ((param->zone == GENDIG_ZONE_DATA) && (param->key_id <= 15)) {
		param->temp_key->gen_data = 1;
		param->temp_key->key_id = (param->key_id & 0xF);    // mask lower 4-bit only
	} 
	else {
		param->temp_key->gen_data = 0;
		param->temp_key->key_id = 0;
	}

	return SHA204_SUCCESS;
}


/** \brief This function combines a key with the TempKey.
 
Used in conjunction with DeriveKey command, the key derived by this function will match the key in the device.
Two kinds of operation are supported:
<ul>
<li>Roll Key operation: target_key and parent_key parameters should be set to point to the same location (TargetKey).</li>
<li>Create Key operation: target_key should be set to point to TargetKey, parent_key should be set to point to ParentKey.</li>
</ul>
After executing this function, the initial value of target_key will be overwritten with the derived key.
The TempKey should be valid (temp_key.valid = 1) before executing this function.
 
 * \param[in, out] param pointer to parameter structure
 * \return status of the operation
 */
uint8_t sha204h_derive_key(struct sha204h_derive_key_in_out *param)
{
	uint8_t temporary[SHA204_MSG_SIZE_DERIVE_KEY];
	uint8_t *p_temp;

	// Check parameters
	if (!param->parent_key || !param->target_key || !param->temp_key
		|| (param->random & ~DERIVE_KEY_RANDOM_FLAG) || (param->target_key_id > SHA204_KEY_ID_MAX))
		return SHA204_BAD_PARAM;

	// Check TempKey fields validity (TempKey is always used)
	if (// TempKey.CheckFlag must be 0 and TempKey.Valid must be 1
		param->temp_key->check_flag	|| (param->temp_key->valid != 1)
		// The random parameter bit 2 must match temp_key.source_flag
		// Logical not (!) is used to evaluate the expression to TRUE / FALSE first before comparison (!=).
		|| (!(param->random & DERIVE_KEY_RANDOM_FLAG) != !(param->temp_key->source_flag))
		)
	{
		// Invalidate TempKey, then return
		param->temp_key->valid = 0;
		return SHA204_CMD_FAIL;
	}

	// Start calculation
	p_temp = temporary;

	// (1) 32 bytes parent key
	memcpy(p_temp, param->parent_key, SHA204_KEY_SIZE);
	p_temp += SHA204_KEY_SIZE;

	// (2) 1 byte Opcode
	*p_temp++ = SHA204_DERIVE_KEY;

	// (3) 1 byte Param1 (random)
	*p_temp++ = param->random;

	// (4) 2 bytes Param2 (keyID)
	*p_temp++ = param->target_key_id & 0xFF;
	*p_temp++ = (param->target_key_id >> 8) & 0xFF;

	// (5) 1 byte SN[8] = 0xEE
	*p_temp++ = SHA204_SN_8;

	// (6) 2 bytes SN[0:1] = 0x0123
	*p_temp++ = SHA204_SN_0;
	*p_temp++ = SHA204_SN_1;

	// (7) 25 zeros
	memset(p_temp, 0, SHA204_DERIVE_KEY_ZEROS_SIZE);
	p_temp += SHA204_DERIVE_KEY_ZEROS_SIZE;
	
	// (8) 32 bytes TempKey
	memcpy(p_temp, param->temp_key->value, SHA204_KEY_SIZE);
	p_temp += SHA204_KEY_SIZE;

	// Calculate SHA256 to get the derived key.
	sha204h_calculate_sha256(SHA204_MSG_SIZE_DERIVE_KEY, temporary, param->target_key);

	// Update TempKey fields
	param->temp_key->valid = 0;

	return SHA204_SUCCESS;
}


/** \brief This function calculates the input MAC for a DeriveKey command.
 
The DeriveKey command will need an input MAC if SlotConfig[TargetKey].Bit15 is set.
 
 * \param[in, out] param pointer to parameter structure
 * \return status of the operation
 */
uint8_t sha204h_derive_key_mac(struct sha204h_derive_key_mac_in_out *param)
{
	uint8_t temporary[SHA204_MSG_SIZE_DERIVE_KEY_MAC];
	uint8_t *p_temp;

	// Check parameters
	if (!param->parent_key || !param->mac || (param->random & ~DERIVE_KEY_RANDOM_FLAG)
									|| (param->target_key_id > SHA204_KEY_ID_MAX))
		return SHA204_BAD_PARAM;

	// Start calculation
	p_temp = temporary;

	// (1) 32 bytes parent key
	memcpy(p_temp, param->parent_key, SHA204_KEY_SIZE);
	p_temp += SHA204_KEY_SIZE;

	// (2) 1 byte Opcode
	*p_temp++ = SHA204_DERIVE_KEY;

	// (3) 1 byte Param1 (random)
	*p_temp++ = param->random;

	// (4) 2 bytes Param2 (keyID)
	*p_temp++ = param->target_key_id & 0xFF;
	*p_temp++ = (param->target_key_id >> 8) & 0xFF;

	// (5) 1 byte SN[8] = 0xEE
	*p_temp++ = SHA204_SN_8;

	// (6) 2 bytes SN[0:1] = 0x0123
	*p_temp++ = SHA204_SN_0;
	*p_temp++ = SHA204_SN_1;

	// Calculate SHA256 to get the input MAC for DeriveKey command
	sha204h_calculate_sha256(SHA204_MSG_SIZE_DERIVE_KEY_MAC, temporary, param->mac);

	return SHA204_SUCCESS;
}


/** \brief This function encrypts 32-byte plain text data to be written using Write opcode, and optionally calculates input MAC.
 
To use this function, first the nonce must be valid and synchronized between device and application.
The application sends a GenDig command to the device, using a parent key. If the Data zone has been locked, this is
specified by SlotConfig.WriteKey. The device updates its TempKey when executing the command.
The application then updates its own TempKey using the GenDig calculation function, using the same key.
The application passes the plain text data to the encryption function.\n
If input MAC is needed the application must pass a valid pointer to buffer in the "mac" command parameter.
If input MAC is not needed the application can pass a NULL pointer in the "mac" command parameter.
The function encrypts the data and optionally calculates the input MAC, and returns it to the application.
Using these encrypted data and the input MAC, the application sends a Write command to the Device. The device
validates the MAC, then decrypts and writes the data.\n
The encryption function does not check whether the TempKey has been generated by the correct ParentKey for the
corresponding zone. Therefore, to get a correct result after the Data and OTP zones have been locked, the application
has to make sure that prior GenDig calculation was done using the correct ParentKey.
 
 * \param[in, out] param pointer to parameter structure
 * \return status of the operation
 */
uint8_t sha204h_encrypt(struct sha204h_encrypt_in_out *param)
{
	uint8_t temporary[SHA204_MSG_SIZE_ENCRYPT_MAC];
	uint8_t i;
	uint8_t *p_temp;

	// Check parameters
	if (!param->crypto_data || !param->temp_key || (param->zone & ~WRITE_ZONE_MASK))
		return SHA204_BAD_PARAM;

	// Check TempKey fields validity, and illegal address
	// Note that if temp_key.key_id is not checked,
	//   we cannot make sure if the key used in previous GenDig IS equal to
	//   the key pointed by SlotConfig.WriteKey in the device.
	if (// TempKey.CheckFlag must be 0
		param->temp_key->check_flag
		// TempKey.Valid must be 1
		|| (param->temp_key->valid != 1)
		// TempKey.GenData must be 1
		|| (param->temp_key->gen_data != 1)
		// TempKey.SourceFlag must be 0 (random)
		|| param->temp_key->source_flag
		// Illegal address
		|| (param->address & ~SHA204_ADDRESS_MASK)
		)
	{
		// Invalidate TempKey, then return
		param->temp_key->valid = 0;
		return SHA204_CMD_FAIL;
	}

	// If the pointer *mac is provided by the caller then calculate input MAC
	if (param->mac) {
		// Start calculation
		p_temp = temporary;

		// (1) 32 bytes parent key
		memcpy(p_temp, param->temp_key->value, SHA204_KEY_SIZE);
		p_temp += SHA204_KEY_SIZE;

		// (2) 1 byte Opcode
		*p_temp++ = SHA204_WRITE;

		// (3) 1 byte Param1 (zone)
		*p_temp++ = param->zone;

		// (4) 2 bytes Param2 (address)
		*p_temp++ = param->address & 0xFF;
		*p_temp++ = (param->address >> 8) & 0xFF;

		// (5) 1 byte SN[8] = 0xEE
		*p_temp++ = SHA204_SN_8;

		// (6) 2 bytes SN[0:1] = 0x0123
		*p_temp++ = SHA204_SN_0;
		*p_temp++ = SHA204_SN_1;

		// (7) 25 zeros
		memset(p_temp, 0, SHA204_GENDIG_ZEROS_SIZE);
		p_temp += SHA204_GENDIG_ZEROS_SIZE;

		// (8) 32 bytes data
		memcpy(p_temp, param->crypto_data, SHA204_KEY_SIZE);

		// Calculate SHA256 to get the input MAC
		sha204h_calculate_sha256(SHA204_MSG_SIZE_ENCRYPT_MAC, temporary, param->mac);
	}

	// Encrypt by XOR-ing Data with the TempKey
	for (i = 0; i < SHA204_KEY_SIZE; i++)
		param->crypto_data[i] ^= param->temp_key->value[i];

	// Update TempKey fields
	param->temp_key->valid = 0;

	return SHA204_SUCCESS;
}


/** \brief This function decrypts 32-byte encrypted data received with the Read command.
 
To use this function, first the nonce must be valid and synchronized between device and application.
The application sends a GenDig command to the Device, using a key specified by SlotConfig.ReadKey.
The device updates its TempKey.
The application then updates its own TempKey using the GenDig calculation function, using the same key.
The application sends a Read command to the device for a user zone configured with EncryptRead.
The device encrypts 32-byte zone content, and outputs it to the host.
The application passes these encrypted data to this decryption function. The function decrypts the data and returns them.
TempKey must be updated by GenDig using a ParentKey as specified by SlotConfig.ReadKey before executing this function.
The decryption function does not check whether the TempKey has been generated by a correct ParentKey for the corresponding zone.
Therefore to get a correct result, the application has to make sure that prior GenDig calculation was done using correct ParentKey.
 
 * \param[in, out] param pointer to parameter structure
 * \return status of the operation
 */
uint8_t sha204h_decrypt(struct sha204h_decrypt_in_out *param)
{
	uint8_t i;

	// Check parameters
	if (!param->crypto_data || !param->temp_key)
		return SHA204_BAD_PARAM;

	// Check TempKey fields validity
	// Note that if temp_key.key_id is not checked,
	// we cannot make sure if the key used in previous GenDig IS equal to
	// the key pointed by SlotConfig.ReadKey in the device.
	if (// TempKey.CheckFlag must be 0
		param->temp_key->check_flag
		// TempKey.Valid must be 1
		|| (param->temp_key->valid != 1)
		// TempKey.GenData must be 1
		|| (param->temp_key->gen_data != 1)
		// TempKey.SourceFlag must be 0 (random)
		|| param->temp_key->source_flag
		)
	{
		// Invalidate TempKey, then return
		param->temp_key->valid = 0;
		return SHA204_CMD_FAIL;
	}

	// Decrypt by XOR-ing Data with the TempKey
	for (i = 0; i < SHA204_KEY_SIZE; i++) {
		param->crypto_data[i] ^= param->temp_key->value[i];
	}

	// Update TempKey fields
	param->temp_key->valid = 0;

	return SHA204_SUCCESS;
}


/** \brief This function calculates the packet CRC.
 
crc_register is initialized with *crc, so it can be chained to calculate CRC from a large array of data.
For the first calculation or calculation without chaining, crc[0] and crc[1] values must be initialized
to 0 by the caller.
 
 \param[in] length number of bytes in buffer
 \param[in] data pointer to data for which CRC should be calculated
 \param[out] crc pointer to 16-bit CRC
*/
void sha204h_calculate_crc_chain(uint8_t length, uint8_t *data, uint8_t *crc)
{
	uint8_t counter;
	uint16_t crc_register = 0;
	uint16_t polynom = 0x8005;
	uint8_t shift_register;
	uint8_t data_bit, crc_bit;

	crc_register = (((uint16_t) crc[0]) & 0x00FF) | (((uint16_t) crc[1]) << 8);

	for (counter = 0; counter < length; counter++) {
	  for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1) {
		 data_bit = (data[counter] & shift_register) ? 1 : 0;
		 crc_bit = crc_register >> 15;

		 // Shift CRC to the left by 1.
		 crc_register <<= 1;

		 if ((data_bit ^ crc_bit) != 0)
			crc_register ^= polynom;
	  }
	}

	crc[0] = (uint8_t) (crc_register & 0x00FF);
	crc[1] = (uint8_t) (crc_register >> 8);
}


#define rotate_right(value, places) ((value >> places) | (value << (32 - places)))
#define SHA256_BLOCK_SIZE   (64)   // bytes


/** \brief This function creates a SHA256 digest on a little-endian system.
 *
 * Limitations: This function was implemented with the ATSHA204 CryptoAuth device
 * in mind. It will therefore only work for length values of len % 64 < 62.
 *
 * \param[in] len byte length of message
 * \param[in] message pointer to message
 * \param[out] digest SHA256 of message
 */
void sha204h_calculate_sha256(int32_t len, uint8_t *message, uint8_t *digest)
{
	int32_t j, swap_counter, len_mod = len % sizeof(int32_t);
	uint32_t i, w_index;
	int32_t message_index = 0;
	uint32_t padded_len = len + 8; // 8 bytes for bit length
	uint32_t bit_len = len * 8;
	uint32_t s0, s1;
	uint32_t t1, t2;
	uint32_t maj, ch;
	uint32_t word_value;
	uint32_t rotate_register[8];

	union {
		uint32_t w_word[SHA256_BLOCK_SIZE];
		uint8_t w_byte[SHA256_BLOCK_SIZE * sizeof(int32_t)];
	} w_union;

	uint32_t hash[] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372,	0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};

	const uint32_t k[] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	// Process message.
	while (message_index <= padded_len) {

		// Break message into 64-byte blocks.
		w_index = 0;
		do {
			// Copy message chunk of four bytes (size of integer) into compression array.
			if (message_index < (len - len_mod)) {
				for (swap_counter = sizeof(int32_t) - 1; swap_counter >= 0; swap_counter--)
					// No padding needed. Swap four message bytes to chunk array.
					w_union.w_byte[swap_counter + w_index] = message[message_index++];

				w_index += sizeof(int32_t);
			}
			else {
				// We reached last complete word of message {len - (len mod 4)}.
				// Swap remaining bytes if any, append '1' bit and pad remaining
				// bytes of the last word.
				for (swap_counter = sizeof(int32_t) - 1;
						swap_counter >= sizeof(int32_t) - len_mod; swap_counter--)
					w_union.w_byte[swap_counter + w_index] = message[message_index++];
				w_union.w_byte[swap_counter + w_index] = 0x80;
				for (swap_counter--; swap_counter >= 0; swap_counter--)
					w_union.w_byte[swap_counter + w_index] = 0;

				// Switch to word indexing.
				w_index += sizeof(int32_t);
				w_index /= sizeof(int32_t);

				// Pad last block with zeros to a block length % 56 = 0
				// and pad the four high bytes of "len" since we work only
				// with integers and not with long integers.
				while (w_index < 15)
					 w_union.w_word[w_index++] = 0;
				// Append original message length as 32-bit integer.
				w_union.w_word[w_index] = bit_len;
				// Indicate that the last block is being processed.
				message_index += SHA256_BLOCK_SIZE;
				// We are done with pre-processing last block.
				break;
			}
		} while (message_index % SHA256_BLOCK_SIZE);
		// Created one block.

		w_index = 16;
		while (w_index < SHA256_BLOCK_SIZE) {
			// right rotate for 32-bit variable in C: (value >> places) | (value << 32 - places)
			word_value = w_union.w_word[w_index - 15];
			s0 = rotate_right(word_value, 7) ^ rotate_right(word_value, 18) ^ (word_value >> 3);

			word_value = w_union.w_word[w_index - 2];
			s1 = rotate_right(word_value, 17) ^ rotate_right(word_value, 19) ^ (word_value >> 10);

			w_union.w_word[w_index] = w_union.w_word[w_index - 16] + s0 + w_union.w_word[w_index - 7] + s1;

			w_index++;
		}

		// Initialize hash value for this chunk.
		for (i = 0; i < 8; i++)
			rotate_register[i] = hash[i];

		// hash calculation loop
		for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
			s0 = rotate_right(rotate_register[0], 2)
				^ rotate_right(rotate_register[0], 13)
				^ rotate_right(rotate_register[0], 22);
			maj = (rotate_register[0] & rotate_register[1])
				^ (rotate_register[0] & rotate_register[2])
				^ (rotate_register[1] & rotate_register[2]);
			t2 = s0 + maj;
			s1 = rotate_right(rotate_register[4], 6)
				^ rotate_right(rotate_register[4], 11)
				^ rotate_right(rotate_register[4], 25);
			ch =  (rotate_register[4] & rotate_register[5])
				^ (~rotate_register[4] & rotate_register[6]);
			t1 = rotate_register[7] + s1 + ch + k[i] + w_union.w_word[i];

			rotate_register[7] = rotate_register[6];
			rotate_register[6] = rotate_register[5];
			rotate_register[5] = rotate_register[4];
			rotate_register[4] = rotate_register[3] + t1;
			rotate_register[3] = rotate_register[2];
			rotate_register[2] = rotate_register[1];
			rotate_register[1] = rotate_register[0];
			rotate_register[0] = t1 + t2;
		}

	    // Add the hash of this block to current result.
		for (i = 0; i < 8; i++)
			hash[i] += rotate_register[i];
	}

	// All blocks have been processed.
	// Concatenate the hashes to produce digest, MSB of every hash first.
	for (i = 0; i < 8; i++) {
		for (j = sizeof(int32_t) - 1; j >= 0; j--, hash[i] >>= 8)
			digest[i * sizeof(int32_t) + j] = hash[i] & 0xFF;
	}
}
