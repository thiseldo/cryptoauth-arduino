/** \file
 *  \brief Command Marshaling Layer of ATSHA204 Library
 *  \author Atmel Crypto Products
 *  \date   January 9, 2013

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
#include "sha204_lib_return_codes.h"   // declarations of function return codes
#include "sha204_comm_marshaling.h"    // definitions and declarations for the Command Marshaling module


// Define this to compile and link this function.
//#define SHA204_CHECK_PARAMETERS

/** \ingroup atsha204_command_marshaling
 * \brief This function checks the parameters for sha204m_execute().
 *
 *
 * \param[in] op_code command op-code
 * \param[in] param1 first parameter
 * \param[in] param2 second parameter
 * \param[in] datalen1 number of bytes in first data block
 * \param[in] data1 pointer to first data block
 * \param[in] datalen2 number of bytes in second data block
 * \param[in] data2 pointer to second data block
 * \param[in] datalen3 number of bytes in third data block
 * \param[in] data3 pointer to third data block
 * \param[in] tx_size size of tx buffer
 * \param[in] tx_buffer pointer to tx buffer
 * \param[in] rx_size size of rx buffer
 * \param[out] rx_buffer pointer to rx buffer
 * \return status of the operation
 */
uint8_t sha204m_check_parameters(uint8_t op_code, uint8_t param1, uint16_t param2,
		uint8_t datalen1, uint8_t *data1, uint8_t datalen2, uint8_t *data2, uint8_t datalen3, uint8_t *data3,
		uint8_t tx_size, uint8_t *tx_buffer, uint8_t rx_size, uint8_t *rx_buffer)
{
#ifdef SHA204_CHECK_PARAMETERS

	uint8_t len = datalen1 + datalen2 + datalen3 + SHA204_CMD_SIZE_MIN;
	if (!tx_buffer || (tx_size < len) || (rx_size < SHA204_RSP_SIZE_MIN) || !rx_buffer)
		return SHA204_BAD_PARAM;

	if ((datalen1 > 0 && !data1) || (datalen2 > 0 && !data2) || (datalen3 > 0 && !data3))
		return SHA204_BAD_PARAM;

	// Check parameters depending on op-code.
	switch (op_code) {
	case SHA204_CHECKMAC:
		if (!data1 || !data2 || (param1 & ~CHECKMAC_MODE_MASK) || (param2 > SHA204_KEY_ID_MAX))
			// Neither data1 nor data2 can be null.
			// param1 has to match an allowed CheckMac mode.
			// key_id > 15 not allowed
			return SHA204_BAD_PARAM;
		break;

	case SHA204_DERIVE_KEY:
		if (param2 > SHA204_KEY_ID_MAX)
			// key_id > 15 not allowed
			return SHA204_BAD_PARAM;
		break;

	case SHA204_DEVREV:
		// Neither parameters nor data are used by this command.
		break;

	case SHA204_GENDIG:
		if ((param1 != GENDIG_ZONE_OTP) && (param1 != GENDIG_ZONE_DATA))
			// param1 has to be GENDIG_ZONE_CONFIG.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_HMAC:
		if (param1 & ~HMAC_MODE_MASK)
			// param1 has to match an allowed HMAC mode.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_LOCK:
		if ((param1 & ~LOCK_ZONE_MASK)
					|| ((param1 & LOCK_ZONE_NO_CRC) && param2))
			// param1 has to match an allowed Lock mode.
			// If no CRC is required the CRC should be 0.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_MAC:
		if ((param1 & ~MAC_MODE_MASK)
					|| (!(param1 & MAC_MODE_BLOCK2_TEMPKEY) && !data1))
			// param1 has to match an allowed MAC mode.
			// If the MAC mode requires challenge data, data1 should not be null.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_NONCE:
		if (!data1 || (param1 > NONCE_MODE_PASSTHROUGH)	|| (param1 == NONCE_MODE_INVALID))
			// data1 cannot be null.
			// param1 has to match an allowed Nonce mode.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_PAUSE:
		// param1 can have any value. param2 and data are not used by this command.
		break;

	case SHA204_RANDOM:
		if (param1 > RANDOM_NO_SEED_UPDATE)
			// param1 has to match an allowed Random mode.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_READ:
		if ((param1 & ~READ_ZONE_MASK)
					|| ((param1 & READ_ZONE_MODE_32_BYTES) && (param1 == SHA204_ZONE_OTP)))
			// param1 has to match an allowed Read mode.
			// A 32-byte block cannot be read from the OTP zone.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_UPDATE_EXTRA:
		if (param1 > UPDATE_CONFIG_BYTE_86)
			// param1 has to match an allowed UpdateExtra mode.
			return SHA204_BAD_PARAM;
		break;

	case SHA204_WRITE:
		if (!data1 || (param1 & ~WRITE_ZONE_MASK))
			// data1 cannot be null.
			// param1 has to match an allowed Write mode.
			return SHA204_BAD_PARAM;
		break;

	default:
		// unknown op-code
		return SHA204_BAD_PARAM;
	}
#endif

	return SHA204_SUCCESS;
}


/** \brief This function creates a command packet, sends it, and receives its response.
 *
 * \param[in] op_code command op-code
 * \param[in] param1 first parameter
 * \param[in] param2 second parameter
 * \param[in] datalen1 number of bytes in first data block
 * \param[in] data1 pointer to first data block
 * \param[in] datalen2 number of bytes in second data block
 * \param[in] data2 pointer to second data block
 * \param[in] datalen3 number of bytes in third data block
 * \param[in] data3 pointer to third data block
 * \param[in] tx_size size of tx buffer
 * \param[in] tx_buffer pointer to tx buffer
 * \param[in] rx_size size of rx buffer
 * \param[out] rx_buffer pointer to rx buffer
 * \return status of the operation
 */
uint8_t sha204m_execute(uint8_t op_code, uint8_t param1, uint16_t param2,
			uint8_t datalen1, uint8_t *data1, uint8_t datalen2, uint8_t *data2, uint8_t datalen3, uint8_t *data3,
			uint8_t tx_size, uint8_t *tx_buffer, uint8_t rx_size, uint8_t *rx_buffer)
{
	uint8_t poll_delay, poll_timeout, response_size;
	uint8_t *p_buffer;
	uint8_t len;

	// Define SHA204_CHECK_PARAMETERS to compile and link this feature.
	uint8_t ret_code = sha204m_check_parameters(op_code, param1, param2,
				datalen1, data1, datalen2, data2, datalen3, data3, 
				tx_size, tx_buffer, rx_size, rx_buffer);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	// Supply delays and response size.
	switch (op_code) {
	case SHA204_CHECKMAC:
		poll_delay = CHECKMAC_DELAY;
		poll_timeout = CHECKMAC_EXEC_MAX - CHECKMAC_DELAY;
		response_size = CHECKMAC_RSP_SIZE;
		break;

	case SHA204_DERIVE_KEY:
		poll_delay = DERIVE_KEY_DELAY;
		poll_timeout = DERIVE_KEY_EXEC_MAX - DERIVE_KEY_DELAY;
		response_size = DERIVE_KEY_RSP_SIZE;
		break;

	case SHA204_DEVREV:
		poll_delay = DEVREV_DELAY;
		poll_timeout = DEVREV_EXEC_MAX - DEVREV_DELAY;
		response_size = DEVREV_RSP_SIZE;
		break;

	case SHA204_GENDIG:
		poll_delay = GENDIG_DELAY;
		poll_timeout = GENDIG_EXEC_MAX - GENDIG_DELAY;
		response_size = GENDIG_RSP_SIZE;
		break;

	case SHA204_HMAC:
		poll_delay = HMAC_DELAY;
		poll_timeout = HMAC_EXEC_MAX - HMAC_DELAY;
		response_size = HMAC_RSP_SIZE;
		break;

	case SHA204_LOCK:
		poll_delay = LOCK_DELAY;
		poll_timeout = LOCK_EXEC_MAX - LOCK_DELAY;
		response_size = LOCK_RSP_SIZE;
		break;

	case SHA204_MAC:
		poll_delay = MAC_DELAY;
		poll_timeout = MAC_EXEC_MAX - MAC_DELAY;
		response_size = MAC_RSP_SIZE;
		break;

	case SHA204_NONCE:
		poll_delay = NONCE_DELAY;
		poll_timeout = NONCE_EXEC_MAX - NONCE_DELAY;
		response_size = param1 == NONCE_MODE_PASSTHROUGH
							? NONCE_RSP_SIZE_SHORT : NONCE_RSP_SIZE_LONG;
		break;

	case SHA204_PAUSE:
		poll_delay = PAUSE_DELAY;
		poll_timeout = PAUSE_EXEC_MAX - PAUSE_DELAY;
		response_size = PAUSE_RSP_SIZE;
		break;

	case SHA204_RANDOM:
		poll_delay = RANDOM_DELAY;
		poll_timeout = RANDOM_EXEC_MAX - RANDOM_DELAY;
		response_size = RANDOM_RSP_SIZE;
		break;

	case SHA204_READ:
		poll_delay = READ_DELAY;
		poll_timeout = READ_EXEC_MAX - READ_DELAY;
		response_size = (param1 & SHA204_ZONE_COUNT_FLAG)
							? READ_32_RSP_SIZE : READ_4_RSP_SIZE;
		break;

	case SHA204_UPDATE_EXTRA:
		poll_delay = UPDATE_DELAY;
		poll_timeout = UPDATE_EXEC_MAX - UPDATE_DELAY;
		response_size = UPDATE_RSP_SIZE;
		break;

	case SHA204_WRITE:
		poll_delay = WRITE_DELAY;
		poll_timeout = WRITE_EXEC_MAX - WRITE_DELAY;
		response_size = WRITE_RSP_SIZE;
		break;

	default:
		poll_delay = 0;
		poll_timeout = SHA204_COMMAND_EXEC_MAX;
		response_size = rx_size;
		break;
	}

	// Assemble command.
	len = datalen1 + datalen2 + datalen3 + SHA204_CMD_SIZE_MIN;
	p_buffer = tx_buffer;
	*p_buffer++ = len;
	*p_buffer++ = op_code;
	*p_buffer++ = param1;
	*p_buffer++ = param2 & 0xFF;
	*p_buffer++ = param2 >> 8;

	if (datalen1 > 0) {
		memcpy(p_buffer, data1, datalen1);
		p_buffer += datalen1;
	}
	if (datalen2 > 0) {
		memcpy(p_buffer, data2, datalen2);
		p_buffer += datalen2;
	}
	if (datalen3 > 0) {
		memcpy(p_buffer, data3, datalen3);
		p_buffer += datalen3;
	}

	sha204c_calculate_crc(len - SHA204_CRC_SIZE, tx_buffer, p_buffer);

	// Send command and receive response.
	return sha204c_send_and_receive(&tx_buffer[0], response_size,
				&rx_buffer[0],	poll_delay, poll_timeout);
}


/** \brief This function sends a CheckMAC command to the device.
 *
 * \param[in]  tx_buffer pointer to transmit buffer
 * \param[out] rx_buffer pointer to receive buffer
 * \param[in]  mode selects the hash inputs
 * \param[in]  key_id slot index of key
 * \param[in]  client_challenge pointer to client challenge (ignored if mode bit 0 is set)
 * \param[in]  client_response pointer to client response
 * \param[in]  other_data pointer to 13 bytes of data used in the client command
 * \return status of the operation
 */
uint8_t sha204m_check_mac(uint8_t *tx_buffer, uint8_t *rx_buffer,
			uint8_t mode, uint8_t key_id, uint8_t *client_challenge, uint8_t *client_response, uint8_t *other_data)
{
	if (!tx_buffer || !rx_buffer || !client_response || !other_data
		|| (mode & ~CHECKMAC_MODE_MASK)	|| (key_id > SHA204_KEY_ID_MAX))
		// no null pointers allowed
		// mode has to match an allowed CheckMac mode.
		// key_id > 15 not allowed
		return SHA204_BAD_PARAM;

	tx_buffer[SHA204_COUNT_IDX] = CHECKMAC_COUNT;
	tx_buffer[SHA204_OPCODE_IDX] = SHA204_CHECKMAC;
	tx_buffer[CHECKMAC_MODE_IDX] = mode & CHECKMAC_MODE_MASK;
	tx_buffer[CHECKMAC_KEYID_IDX]= key_id;
	tx_buffer[CHECKMAC_KEYID_IDX + 1] = 0;
	if (!client_challenge)
		memset(&tx_buffer[CHECKMAC_CLIENT_CHALLENGE_IDX], 0, CHECKMAC_CLIENT_CHALLENGE_SIZE);
	else
		memcpy(&tx_buffer[CHECKMAC_CLIENT_CHALLENGE_IDX], client_challenge, CHECKMAC_CLIENT_CHALLENGE_SIZE);

	memcpy(&tx_buffer[CHECKMAC_CLIENT_RESPONSE_IDX], client_response, CHECKMAC_CLIENT_RESPONSE_SIZE);
	memcpy(&tx_buffer[CHECKMAC_DATA_IDX], other_data, CHECKMAC_OTHER_DATA_SIZE);

	return sha204c_send_and_receive(&tx_buffer[0], CHECKMAC_RSP_SIZE, &rx_buffer[0],
				CHECKMAC_DELAY, CHECKMAC_EXEC_MAX - CHECKMAC_DELAY);
}


/** \brief This function sends a DeriveKey command to the device.
 *
 * \param[in]  tx_buffer pointer to transmit buffer
 * \param[out] rx_buffer pointer to receive buffer
 * \param[in]  random type of source key (has to match TempKey.SourceFlag)
 * \param[in]  target_key slot index of key (0..15); not used if random is 1
 * \param[in]  mac pointer to optional MAC
 * \return status of the operation
 */
uint8_t sha204m_derive_key(uint8_t *tx_buffer, uint8_t *rx_buffer,
			uint8_t random, uint8_t target_key, uint8_t *mac)
{
	if (!tx_buffer || !rx_buffer || (random & ~DERIVE_KEY_RANDOM_FLAG)
				 || (target_key > SHA204_KEY_ID_MAX))
		// no null pointers allowed
		// random has to match an allowed DeriveKey mode.
		// target_key > 15 not allowed
		return SHA204_BAD_PARAM;

	tx_buffer[SHA204_OPCODE_IDX] = SHA204_DERIVE_KEY;
	tx_buffer[DERIVE_KEY_RANDOM_IDX] = random;
	tx_buffer[DERIVE_KEY_TARGETKEY_IDX] = target_key;
	tx_buffer[DERIVE_KEY_TARGETKEY_IDX + 1] = 0;
	if (mac != NULL)
	{
		memcpy(&tx_buffer[DERIVE_KEY_MAC_IDX], mac, DERIVE_KEY_MAC_SIZE);
		tx_buffer[SHA204_COUNT_IDX] = DERIVE_KEY_COUNT_LARGE;
	}
	else
		tx_buffer[SHA204_COUNT_IDX] = DERIVE_KEY_COUNT_SMALL;

	return sha204c_send_and_receive(&tx_buffer[0], DERIVE_KEY_RSP_SIZE, &rx_buffer[0],
				DERIVE_KEY_DELAY, DERIVE_KEY_EXEC_MAX - DERIVE_KEY_DELAY);
}


/** \brief This function sends a DevRev command to the device.
 *
 * \param[in]  tx_buffer pointer to transmit buffer
 * \param[out] rx_buffer pointer to receive buffer
 * \return status of the operation
 */
uint8_t sha204m_dev_rev(uint8_t *tx_buffer, uint8_t *rx_buffer)
{
	if (!tx_buffer || !rx_buffer)
		// no null pointers allowed
		return SHA204_BAD_PARAM;

	tx_buffer[SHA204_COUNT_IDX] = DEVREV_COUNT;
	tx_buffer[SHA204_OPCODE_IDX] = SHA204_DEVREV;

	// Parameters are 0.
	tx_buffer[DEVREV_PARAM1_IDX] =
	tx_buffer[DEVREV_PARAM2_IDX] =
	tx_buffer[DEVREV_PARAM2_IDX + 1] = 0;

	return sha204c_send_and_receive(&tx_buffer[0], DEVREV_RSP_SIZE, &rx_buffer[0],
				DEVREV_DELAY, DEVREV_EXEC_MAX - DEVREV_DELAY);
}


/** \brief This function sends a GenDig command to the device.
 *
 * \param[in]  tx_buffer pointer to transmit buffer
 * \param[out] rx_buffer pointer to receive buffer
 * \param[in]  zone 0: config, zone 1: OTP zone, 2: data zone
 * \param[in]  key_id zone 1: OTP block; zone 2: key id
 * \param[in]  other_data pointer to 4 bytes of data when using CheckOnly key
 * \return status of the operation
 */
uint8_t sha204m_gen_dig(uint8_t *tx_buffer, uint8_t *rx_buffer,
			uint8_t zone, uint8_t key_id, uint8_t *other_data)
{
	if (!tx_buffer || !rx_buffer || (zone > GENDIG_ZONE_DATA))
		// no null pointers allowed
		// zone has to match a zone (Config, Data, or OTP zone)
		return SHA204_BAD_PARAM;

	if (((zone == GENDIG_ZONE_OTP) && (key_id > SHA204_OTP_BLOCK_MAX))
				|| ((zone == GENDIG_ZONE_DATA) && (key_id > SHA204_KEY_ID_MAX)))
		// If OTP zone is used only valid OTP block values can be used.
		// If Data zone is used key_id > 15 is not allowed.
		return SHA204_BAD_PARAM;

	tx_buffer[SHA204_OPCODE_IDX] = SHA204_GENDIG;
	tx_buffer[GENDIG_ZONE_IDX] = zone;
	tx_buffer[GENDIG_KEYID_IDX] = key_id;
	tx_buffer[GENDIG_KEYID_IDX + 1] = 0;
	if (other_data != NULL)
	{
		memcpy(&tx_buffer[GENDIG_DATA_IDX], other_data, GENDIG_OTHER_DATA_SIZE);
		tx_buffer[SHA204_COUNT_IDX] = GENDIG_COUNT_DATA;
	}
	else
		tx_buffer[SHA204_COUNT_IDX] = GENDIG_COUNT;

	return sha204c_send_and_receive(&tx_buffer[0], GENDIG_RSP_SIZE, &rx_buffer[0],
				GENDIG_DELAY, GENDIG_EXEC_MAX - GENDIG_DELAY);

}


/** \brief This function sends an HMAC command to the device.
 *
 * \param[in]  tx_buffer pointer to transmit buffer
 * \param[out] rx_buffer pointer to receive buffer
 * \param[in]  mode selects the hash inputs
 * \param[in]  key_id slot index of key
 * \return status of the operation
 */
uint8_t sha204m_hmac(uint8_t *tx_buffer, uint8_t *rx_buffer, uint8_t mode, uint16_t key_id)
{
	if (!tx_buffer || !rx_buffer || (mode & ~HMAC_MODE_MASK))
		// no null pointers allowed
		// mode has to match an allowed HMAC mode.
		return SHA204_BAD_PARAM;

	tx_buffer[SHA204_COUNT_IDX] = HMAC_COUNT;
	tx_buffer[SHA204_OPCODE_IDX] = SHA204_HMAC;
	tx_buffer[HMAC_MODE_IDX] = mode;

	// Although valid key identifiers are only
	// from 0 to 15, all 16 bits are used in the HMAC message.
	tx_buffer[HMAC_KEYID_IDX] = key_id & 0xFF;
	tx_buffer[HMAC_KEYID_IDX + 1] = key_id >> 8;

	return sha204c_send_and_receive(&tx_buffer[0], HMAC_RSP_SIZE, &rx_buffer[0],
				HMAC_DELAY, HMAC_EXEC_MAX - HMAC_DELAY);
}


/** \brief This function sends a Lock command to the device.
 *
 * \param[in]  tx_buffer pointer to transmit buffer
 * \param[out] rx_buffer pointer to receive buffer
 * \param[in]  zone zone id to lock
 * \param[in]  summary zone digest
 * \return status of the operation
 */
uint8_t sha204m_lock(uint8_t *tx_buffer, uint8_t *rx_buffer, uint8_t zone, uint16_t summary)
{
	if (!tx_buffer || !rx_buffer || (zone & ~LOCK_ZONE_MASK)
				|| ((zone & LOCK_ZONE_NO_CRC) && summary))
		// no null pointers allowed
		// zone has to match an allowed zone.
		// If no CRC is required summary has to be 0.
		return SHA204_BAD_PARAM;

	tx_buffer[SHA204_COUNT_IDX] = LOCK_COUNT;
	tx_buffer[SHA204_OPCODE_IDX] = SHA204_LOCK;
	tx_buffer[LOCK_ZONE_IDX] = zone & LOCK_ZONE_MASK;
	tx_buffer[LOCK_SUMMARY_IDX]= summary & 0xFF;
	tx_buffer[LOCK_SUMMARY_IDX + 1]= summary >> 8;
	return sha204c_send_and_receive(&tx_buffer[0], LOCK_RSP_SIZE, &rx_buffer[0],
				LOCK_DELAY, LOCK_EXEC_MAX - LOCK_DELAY);
}


/** \brief This function sends a MAC command to the device.
 *
 * \param[in]  tx_buffer pointer to transmit buffer
 * \param[out] rx_buffer pointer to receive buffer
 * \param[in]  mode selects message fields
 * \param[in]  key_id slot index of key
 * \param[in]  challenge pointer to challenge (not used if mode bit 0 is set)
 * \return status of the operation
 */
uint8_t sha204m_mac(uint8_t *tx_buffer, uint8_t *rx_buffer,
			uint8_t mode, uint16_t key_id, uint8_t *challenge)
{
	if (!tx_buffer || !rx_buffer || (mode & ~MAC_MODE_MASK)
				|| (!(mode & MAC_MODE_BLOCK2_TEMPKEY) && !challenge))
		// no null pointers allowed
		// mode has to match an allowed MAC mode.
		// If mode requires challenge data challenge cannot be null.
		return SHA204_BAD_PARAM;

	tx_buffer[SHA204_COUNT_IDX] = MAC_COUNT_SHORT;
	tx_buffer[SHA204_OPCODE_IDX] = SHA204_MAC;
	tx_buffer[MAC_MODE_IDX] = mode;
	tx_buffer[MAC_KEYID_IDX] = key_id & 0xFF;
	tx_buffer[MAC_KEYID_IDX + 1] = key_id >> 8;
	if ((mode & MAC_MODE_BLOCK2_TEMPKEY) == 0)
	{
		memcpy(&tx_buffer[MAC_CHALLENGE_IDX], challenge, MAC_CHALLENGE_SIZE);
		tx_buffer[SHA204_COUNT_IDX] = MAC_COUNT_LONG;
	}

	return sha204c_send_and_receive(&tx_buffer[0], MAC_RSP_SIZE, &rx_buffer[0],
				MAC_DELAY, MAC_EXEC_MAX - MAC_DELAY);
}


/** \brief This function sends a Nonce command to the device.
 *
 * \param[in]  tx_buffer pointer to transmit buffer
 * \param[out] rx_buffer pointer to receive buffer
 * \param[in]  mode controls the mechanism of the internal random number generator and seed update
 * \param[in]  numin pointer to system input\n
 *             (mode = 3: 32 bytes same as in TempKey;\n
 *              mode < 2: 20 bytes\n
 *              mode == 2: not allowed)
 * \return status of the operation
 */
uint8_t sha204m_nonce(uint8_t *tx_buffer, uint8_t *rx_buffer, uint8_t mode, uint8_t *numin)
{
	uint8_t rx_size;

	if (!tx_buffer || !rx_buffer || !numin
				|| (mode > NONCE_MODE_PASSTHROUGH) || (mode == NONCE_MODE_INVALID))
		// no null pointers allowed
		// mode has to match an allowed Nonce mode.
		return SHA204_BAD_PARAM;

	tx_buffer[SHA204_OPCODE_IDX] = SHA204_NONCE;
	tx_buffer[NONCE_MODE_IDX] = mode;

	// 2. parameter is 0.
	tx_buffer[NONCE_PARAM2_IDX] =
	tx_buffer[NONCE_PARAM2_IDX + 1] = 0;

	if (mode != NONCE_MODE_PASSTHROUGH)
	{
		memcpy(&tx_buffer[NONCE_INPUT_IDX], numin, NONCE_NUMIN_SIZE);
		tx_buffer[SHA204_COUNT_IDX] = NONCE_COUNT_SHORT;
		rx_size = NONCE_RSP_SIZE_LONG;
	}
	else
	{
		memcpy(&tx_buffer[NONCE_INPUT_IDX], numin, NONCE_NUMIN_SIZE_PASSTHROUGH);
		tx_buffer[SHA204_COUNT_IDX] = NONCE_COUNT_LONG;
		rx_size = NONCE_RSP_SIZE_SHORT;
	}

	return sha204c_send_and_receive(&tx_buffer[0], rx_size, &rx_buffer[0],
				NONCE_DELAY, NONCE_EXEC_MAX - NONCE_DELAY);
}


/** \brief This function sends a Pause command to the device.
 *
 * \param[in]  tx_buffer pointer to transmit buffer
 * \param[out] rx_buffer pointer to receive buffer
 * \param[in]  selector Devices not matching this value will go into Idle mode.
 * \return status of the operation
 */
uint8_t sha204m_pause(uint8_t *tx_buffer, uint8_t *rx_buffer, uint8_t selector)
{
	if (!tx_buffer || !rx_buffer)
		// no null pointers allowed
		return SHA204_BAD_PARAM;

	tx_buffer[SHA204_COUNT_IDX] = PAUSE_COUNT;
	tx_buffer[SHA204_OPCODE_IDX] = SHA204_PAUSE;
	tx_buffer[PAUSE_SELECT_IDX] = selector;

	// 2. parameter is 0.
	tx_buffer[PAUSE_PARAM2_IDX] =
	tx_buffer[PAUSE_PARAM2_IDX + 1] = 0;

	return sha204c_send_and_receive(&tx_buffer[0], PAUSE_RSP_SIZE, &rx_buffer[0],
				PAUSE_DELAY, PAUSE_EXEC_MAX - PAUSE_DELAY);
}


/** \brief This function sends a Random command to the device.
 *
 * \param[in]  tx_buffer pointer to transmit buffer
 * \param[out] rx_buffer pointer to receive buffer
 * \param[in]  mode 0: update seed; 1: no seed update
 * \return status of the operation
 */
uint8_t sha204m_random(uint8_t *tx_buffer, uint8_t *rx_buffer, uint8_t mode)
{
	if (!tx_buffer || !rx_buffer || (mode > RANDOM_NO_SEED_UPDATE))
		// no null pointers allowed
		// mode has to match an allowed Random mode.
		return SHA204_BAD_PARAM;

	tx_buffer[SHA204_COUNT_IDX] = RANDOM_COUNT;
	tx_buffer[SHA204_OPCODE_IDX] = SHA204_RANDOM;
	tx_buffer[RANDOM_MODE_IDX] = mode & RANDOM_SEED_UPDATE;

	// 2. parameter is 0.
	tx_buffer[RANDOM_PARAM2_IDX] =
	tx_buffer[RANDOM_PARAM2_IDX + 1] = 0;

	return sha204c_send_and_receive(&tx_buffer[0], RANDOM_RSP_SIZE, &rx_buffer[0],
				RANDOM_DELAY, RANDOM_EXEC_MAX - RANDOM_DELAY);
}


/** \brief This function sends a Read command to the device.
 *
 * \param[in]  tx_buffer pointer to transmit buffer
 * \param[out] rx_buffer pointer to receive buffer
 * \param[in]  zone 0: Configuration; 1: OTP; 2: Data
 * \param[in]  address address to read from
 * \return status of the operation
 */
uint8_t sha204m_read(uint8_t *tx_buffer, uint8_t *rx_buffer, uint8_t zone, uint16_t address)
{
	uint8_t rx_size;

	if (!tx_buffer || !rx_buffer || (zone & ~READ_ZONE_MASK)
				|| ((zone & READ_ZONE_MODE_32_BYTES) && (zone == SHA204_ZONE_OTP)))
		// no null pointers allowed
		// zone has to match a valid param1 value.
		// Reading a 32-byte from the OTP zone is not allowed.
		return SHA204_BAD_PARAM;

	address >>= 2;
	if ((zone & SHA204_ZONE_MASK) == SHA204_ZONE_CONFIG) {
		if (address > SHA204_ADDRESS_MASK_CONFIG)
			return SHA204_BAD_PARAM;
	}
	else if ((zone & SHA204_ZONE_MASK) == SHA204_ZONE_OTP) {
		if (address > SHA204_ADDRESS_MASK_OTP)
			return SHA204_BAD_PARAM;
	}
	else if ((zone & SHA204_ZONE_MASK) == SHA204_ZONE_DATA) {
		if (address > SHA204_ADDRESS_MASK)
			return SHA204_BAD_PARAM;
	}

	tx_buffer[SHA204_COUNT_IDX] = READ_COUNT;
	tx_buffer[SHA204_OPCODE_IDX] = SHA204_READ;
	tx_buffer[READ_ZONE_IDX] = zone;
	tx_buffer[READ_ADDR_IDX] = (uint8_t) (address & SHA204_ADDRESS_MASK);
	tx_buffer[READ_ADDR_IDX + 1] = 0;

	rx_size = (zone & SHA204_ZONE_COUNT_FLAG) ? READ_32_RSP_SIZE : READ_4_RSP_SIZE;

	return sha204c_send_and_receive(&tx_buffer[0], rx_size, &rx_buffer[0],
				READ_DELAY, READ_EXEC_MAX - READ_DELAY);
}


/** \brief This function sends an UpdateExtra command to the device.
 *
 * \param[in]  tx_buffer pointer to transmit buffer
 * \param[out] rx_buffer pointer to receive buffer
 * \param[in]  mode 0: update Configuration zone byte 85; 1: byte 86
 * \param[in]  new_value byte to write
 * \return status of the operation
 */
uint8_t sha204m_update_extra(uint8_t *tx_buffer, uint8_t *rx_buffer, uint8_t mode, uint8_t new_value)
{
	if (!tx_buffer || !rx_buffer || (mode > UPDATE_CONFIG_BYTE_86))
		// no null pointers allowed
		// mode has to match an allowed UpdateExtra mode.
		return SHA204_BAD_PARAM;

	tx_buffer[SHA204_COUNT_IDX] = UPDATE_COUNT;
	tx_buffer[SHA204_OPCODE_IDX] = SHA204_UPDATE_EXTRA;
	tx_buffer[UPDATE_MODE_IDX] = mode;
	tx_buffer[UPDATE_VALUE_IDX] = new_value;
	tx_buffer[UPDATE_VALUE_IDX + 1] = 0;

	return sha204c_send_and_receive(&tx_buffer[0], UPDATE_RSP_SIZE, &rx_buffer[0],
				UPDATE_DELAY, UPDATE_EXEC_MAX - UPDATE_DELAY);
}


/**\brief This function sends a Write command to the device.
 *
 * \param[in]  tx_buffer pointer to transmit buffer
 * \param[out] rx_buffer pointer to receive buffer
 * \param[in]  zone 0: Configuration; 1: OTP; 2: Data
 * \param[in]  address address to write to
 * \param[in]  new_value pointer to 32 (zone bit 7 set) or 4 bytes of data
 * \param[in]  mac pointer to MAC (ignored if zone is unlocked)
 * \return status of the operation
 */
uint8_t sha204m_write(uint8_t *tx_buffer, uint8_t *rx_buffer,
			uint8_t zone, uint16_t address, uint8_t *new_value, uint8_t *mac)
{
	uint8_t *p_command;
	uint8_t count;

	if (!tx_buffer || !rx_buffer || !new_value || (zone & ~WRITE_ZONE_MASK))
		// no null pointers allowed
		// zone has to match a valid param1 value.
		return SHA204_BAD_PARAM;

	address >>= 2;
	if ((zone & SHA204_ZONE_MASK) == SHA204_ZONE_CONFIG) {
		if (address > SHA204_ADDRESS_MASK_CONFIG)
			return SHA204_BAD_PARAM;
	}
	else if ((zone & SHA204_ZONE_MASK) == SHA204_ZONE_OTP) {
		if (address > SHA204_ADDRESS_MASK_OTP)
			return SHA204_BAD_PARAM;
	}
	else if ((zone & SHA204_ZONE_MASK) == SHA204_ZONE_DATA) {
		if (address > SHA204_ADDRESS_MASK)
			return SHA204_BAD_PARAM;
	}

	p_command = &tx_buffer[SHA204_OPCODE_IDX];
	*p_command++ = SHA204_WRITE;
	*p_command++ = zone;
	*p_command++ = (uint8_t) (address & SHA204_ADDRESS_MASK);
	*p_command++ = 0;

	count = (zone & SHA204_ZONE_COUNT_FLAG) ? SHA204_ZONE_ACCESS_32 : SHA204_ZONE_ACCESS_4;
	memcpy(p_command, new_value, count);
	p_command += count;

	if (mac != NULL)
	{
		memcpy(p_command, mac, WRITE_MAC_SIZE);
		p_command += WRITE_MAC_SIZE;
	}

	// Supply count.
	tx_buffer[SHA204_COUNT_IDX] = (uint8_t) (p_command - &tx_buffer[0] + SHA204_CRC_SIZE);

	return sha204c_send_and_receive(&tx_buffer[0], WRITE_RSP_SIZE, &rx_buffer[0],
				WRITE_DELAY, WRITE_EXEC_MAX - WRITE_DELAY);
}
