/** \file
 *  \brief Command Marshaling Layer of ECCX08 Library
 *  \author Atmel Crypto Products
 *  \date   October 08, 2013

* \copyright Copyright (c) 2013 Atmel Corporation. All rights reserved.
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

#include <string.h>						// needed for memcpy()

#include "eccX08_lib_return_codes.h"	// declarations of function return codes
#include "eccX08_comm_marshaling.h"		// definitions and declarations for the Command Marshaling module

// Define this to compile and link this function.
//#define ECCX08_CHECK_PARAMETERS

/** \ingroup ateccX08_command_marshaling
 * \brief This function checks the parameters for eccX08m_execute().
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
uint8_t eccX08m_check_parameters(uint8_t op_code, uint8_t param1, uint16_t param2,
	uint8_t datalen1, uint8_t *data1, uint8_t datalen2, uint8_t *data2, uint8_t datalen3, uint8_t *data3,
	uint8_t tx_size, uint8_t *tx_buffer, uint8_t rx_size, uint8_t *rx_buffer)
{
#ifdef ECCX08_CHECK_PARAMETERS
	uint8_t len = datalen1 + datalen2 + datalen3 + ECCX08_CMD_SIZE_MIN;
	if (!tx_buffer || (tx_size < len) || (rx_size < ECCX08_RSP_SIZE_MIN) || !rx_buffer)
		return ECCX08_BAD_PARAM;
		
	if ((datalen1 > 0 && !data1) || (datalen2 > 0 && !data2) || (datalen3 > 0 && !data3))
		return ECCX08_BAD_PARAM;
		
	// Check parameters depending on op-code.
	switch (op_code) {
	case ECCX08_CHECKMAC:
		if (!data1 || !data2 || (param1 & ~CHECKMAC_MODE_MASK) || (param2 > ECCX08_KEY_ID_MAX))
			// Neither data1 nor data2 can be null.
			// param1 has to match an allowed CheckMac mode.
			// key_id > 15 not allowed
			return ECCX08_BAD_PARAM;
		break;
		
	case ECCX08_DERIVE_KEY:
		if (param2 > ECCX08_KEY_ID_MAX)
			// key_id > 15 not allowed
			return ECCX08_BAD_PARAM;
		break;
		
	case ECCX08_GENDIG:
		if ((param1 > GENDIG_ZONE_DATA) || (param2 > ECCX08_KEY_ID_MAX))
			// param1 has to match an allowed GenDig mode.
			// key_id > 15 not allowed
			return ECCX08_BAD_PARAM;
		break;
		
	case ECCX08_GENKEY:
		if ((param1 & ~GENKEY_MODE_MASK) || (param2 > ECCX08_KEY_ID_MAX))
			// param1 has to match an allowed GenKey mode.
			// key_id > 15 not allowed
			return ECCX08_BAD_PARAM;
		break;
		
	case ECCX08_HMAC:
		if (param1 & ~HMAC_MODE_MASK)
			// param1 has to match an allowed HMAC mode.
			return ECCX08_BAD_PARAM;
		break;
		
	case ECCX08_INFO:
		if ((param1 > INFO_MODE_MAX) || (param2 > ECCX08_KEY_ID_MAX))
			// param1 has to match an allowed Info mode.
			// param2 > 15 not allowed (when mode = KeyValid)
			return ECCX08_BAD_PARAM;
		break;
		
	case ECCX08_LOCK:
		if ((param1 & ~LOCK_ZONE_MASK) || ((param1 & LOCK_ZONE_NO_CRC) && param2))
			// param1 has to match an allowed Lock mode.
			// If no CRC is required the CRC should be 0.
			return ECCX08_BAD_PARAM;
		break;
		
	case ECCX08_MAC:
		if ((param1 & ~MAC_MODE_MASK) || (!(param1 & MAC_MODE_BLOCK2_TEMPKEY) && !data1))
			// param1 has to match an allowed MAC mode.
			// If the MAC mode requires challenge data, data1 should not be null.
			return ECCX08_BAD_PARAM;
		break;
		
	case ECCX08_NONCE:
		if (!data1 || (param1 > NONCE_MODE_PASSTHROUGH)	|| (param1 == NONCE_MODE_INVALID))
			// data1 cannot be null.
			// param1 has to match an allowed Nonce mode.
			return ECCX08_BAD_PARAM;
		break;
		
	case ECCX08_PAUSE:
		// param1 can have any value. param2 and data are not used by this command.
		break;
		
	case ECCX08_PRIVWRITE:
		if (!data1 || (param1 & ~PRIVWRITE_ZONE_MASK) || (param2 > ECCX08_KEY_ID_MAX))
			// data1 cannot be null.
			// param1 has to match an allowed PrivWrite mode.
			// key_id > 15 not allowed
			return ECCX08_BAD_PARAM;
		break;
		
	case ECCX08_RANDOM:
		if (param1 > RANDOM_NO_SEED_UPDATE)
			// param1 has to match an allowed Random mode.
			return ECCX08_BAD_PARAM;
		break;
		
	case ECCX08_READ:
		if (param1 & ~READ_ZONE_MASK)
			// param1 has to match an allowed Read mode.
			return ECCX08_BAD_PARAM;
		break;
		
	case ECCX08_SIGN:
		if ((param1 & ~SIGN_MODE_MASK) || (param2 > ECCX08_KEY_ID_MAX))
			// param1 has to match an allowed Sign mode.
			// key_id > 15 not allowed
			return ECCX08_BAD_PARAM;
		break;
		
	case ECCX08_TEMPSENSE:
		// Neither parameters nor data are used by this command.
		break;

	case ECCX08_UPDATE_EXTRA:
		if (param1 > UPDATE_CONFIG_BYTE_85)
			// param1 has to match an allowed UpdateExtra mode.
			return ECCX08_BAD_PARAM;
		break;
		
	case ECCX08_VERIFY:
		if (param1 & ~VERIFY_MODE_MASK) 
			// param1 has to match an allowed Verify mode.
			return ECCX08_BAD_PARAM;
		break;
		
	case ECCX08_WRITE:
		if (!data1 || (param1 & ~WRITE_ZONE_MASK))
			// data1 cannot be null.
			// param1 has to match an allowed Write mode.
			return ECCX08_BAD_PARAM;
		break;
		
	default:
		// unknown op-code
		return ECCX08_BAD_PARAM;
	}
#endif

	return ECCX08_SUCCESS;
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
uint8_t eccX08m_execute(uint8_t op_code, uint8_t param1, uint16_t param2,
	uint8_t datalen1, uint8_t *data1, uint8_t datalen2, uint8_t *data2, uint8_t datalen3, uint8_t *data3,
	uint8_t tx_size, uint8_t *tx_buffer, uint8_t rx_size, uint8_t *rx_buffer)
{
	uint8_t poll_delay, poll_timeout, response_size;
	uint8_t *p_buffer;
	uint8_t len;
	
	// Define ECCX08_CHECK_PARAMETERS to compile and link this feature.
	uint8_t ret_code = eccX08m_check_parameters(op_code, param1, param2,
		datalen1, data1, datalen2, data2, datalen3, data3,
		tx_size, tx_buffer, rx_size, rx_buffer);
	if (ret_code != ECCX08_SUCCESS)
		return ret_code;
		
	// Supply delays and response size.
	switch (op_code)
	{
	case ECCX08_CHECKMAC:
		poll_delay = CHECKMAC_DELAY;
		poll_timeout = CHECKMAC_EXEC_MAX - CHECKMAC_DELAY;
		response_size = CHECKMAC_RSP_SIZE;
		break;
		
	case ECCX08_DERIVE_KEY:
		poll_delay = DERIVE_KEY_DELAY;
		poll_timeout = DERIVE_KEY_EXEC_MAX - DERIVE_KEY_DELAY;
		response_size = DERIVE_KEY_RSP_SIZE;
		break;
		
	case ECCX08_GENDIG:
		poll_delay = GENDIG_DELAY;
		poll_timeout = GENDIG_EXEC_MAX - GENDIG_DELAY;
		response_size = GENDIG_RSP_SIZE;
		break;
		
	case ECCX08_GENKEY:
		poll_delay = GENKEY_DELAY;
		poll_timeout = GENKEY_EXEC_MAX - GENKEY_DELAY;
//	#define GENKEY_RSP_SIZE_MEDIUM			ECCX08_RSP_SIZE_64	//!< response size when generating 256-bit key
//	#define GENKEY_RSP_SIZE_LONG			ECCX08_RSP_SIZE_MAX	//!< response size when generating 283-bit key

		response_size = param1 == GENKEY_MODE_DIGEST //todo: differentiate 256 keys with 283 keys
			? GENKEY_RSP_SIZE_SHORT : GENKEY_RSP_SIZE_MEDIUM;		//GENKEY_RSP_SIZE_LONG;
		break;
		
	case ECCX08_HMAC:
		poll_delay = HMAC_DELAY;
		poll_timeout = HMAC_EXEC_MAX - HMAC_DELAY;
		response_size = HMAC_RSP_SIZE;
		break;
		
	case ECCX08_INFO:
		poll_delay = INFO_DELAY;
		poll_timeout = INFO_EXEC_MAX - INFO_DELAY;
		response_size = INFO_RSP_SIZE;
		break;
		
	case ECCX08_LOCK:
		poll_delay = LOCK_DELAY;
		poll_timeout = LOCK_EXEC_MAX - LOCK_DELAY;
		response_size = LOCK_RSP_SIZE;
		break;
		
	case ECCX08_MAC:
		poll_delay = MAC_DELAY;
		poll_timeout = MAC_EXEC_MAX - MAC_DELAY;
		response_size = MAC_RSP_SIZE;
		break;
		
	case ECCX08_NONCE:
		poll_delay = NONCE_DELAY;
		poll_timeout = NONCE_EXEC_MAX - NONCE_DELAY;
		response_size = param1 == NONCE_MODE_PASSTHROUGH
			? NONCE_RSP_SIZE_SHORT : NONCE_RSP_SIZE_LONG;
		break;
		
	case ECCX08_PAUSE:
		poll_delay = PAUSE_DELAY;
		poll_timeout = PAUSE_EXEC_MAX - PAUSE_DELAY;
		response_size = PAUSE_RSP_SIZE;
		break;
		
	case ECCX08_PRIVWRITE:
		poll_delay = PRIVWRITE_DELAY;
		poll_timeout = PRIVWRITE_EXEC_MAX - PRIVWRITE_DELAY;
		response_size = PRIVWRITE_RSP_SIZE;
		break;
		
	case ECCX08_RANDOM:
		poll_delay = RANDOM_DELAY;
		poll_timeout = RANDOM_EXEC_MAX - RANDOM_DELAY;
		response_size = RANDOM_RSP_SIZE;
		break;
		
	case ECCX08_READ:
		poll_delay = READ_DELAY;
		poll_timeout = READ_EXEC_MAX - READ_DELAY;
		response_size = (param1 & ECCX08_ZONE_COUNT_FLAG)
			? READ_32_RSP_SIZE : READ_4_RSP_SIZE;
		break;
		
	case ECCX08_SIGN:
		poll_delay = SIGN_DELAY;
		poll_timeout = SIGN_EXEC_MAX - SIGN_DELAY;
		//response_size = SIGN_RSP_SIZE_LONG; //todo: differentiate 256 keys with 283 keys
		response_size = SIGN_RSP_SIZE_SHORT;  // 256 bit keys
		break;
		
	case ECCX08_TEMPSENSE:
		poll_delay = TEMPSENSE_DELAY;
		poll_timeout = TEMPSENSE_EXEC_MAX - TEMPSENSE_DELAY;
		response_size = TEMPSENSE_RSP_SIZE;
		break;
		
	case ECCX08_UPDATE_EXTRA:
		poll_delay = UPDATE_DELAY;
		poll_timeout = UPDATE_EXEC_MAX - UPDATE_DELAY;
		response_size = UPDATE_RSP_SIZE;
		break;
		
	case ECCX08_VERIFY:
		poll_delay = VERIFY_DELAY;
		poll_timeout = VERIFY_EXEC_MAX - VERIFY_DELAY;
		response_size = VERIFY_RSP_SIZE;
		break;
		
	case ECCX08_WRITE:
		poll_delay = WRITE_DELAY;
		poll_timeout = WRITE_EXEC_MAX - WRITE_DELAY;
		response_size = WRITE_RSP_SIZE;
		break;
		
	case ECCX08_SHA:
		poll_delay = SHA_DELAY;
		poll_timeout = SHA_EXEC_MAX - SHA_DELAY;
		response_size = param1 == 0x02
			? SHA_RSP_SIZE_LONG : SHA_RSP_SIZE_SHORT;
		break;
		
	case ECCX08_COUNTER:
		poll_delay = COUNTER_DELAY;
		poll_timeout = COUNTER_EXEC_MAX - COUNTER_DELAY;
		response_size = COUNTER_RSP_SIZE;
		break;
		
	case ECCX08_ECDH:
		poll_delay = ECDH_DELAY;
		poll_timeout = ECDH_EXEC_MAX - ECDH_DELAY;
		response_size = rx_size;
		break;
		
	default:
		poll_delay = 0;
		poll_timeout = ECCX08_COMMAND_EXEC_MAX;
		response_size = rx_size;
	}
	
	// Assemble command.
	len = datalen1 + datalen2 + datalen3 + ECCX08_CMD_SIZE_MIN;
	p_buffer = tx_buffer;
	*p_buffer++ = len;
	*p_buffer++ = op_code;
	*p_buffer++ = param1;
	*p_buffer++ = param2 & 0xFF;
	*p_buffer++ = param2 >> 8;
	
	if (datalen1 > 0)
	{
		memcpy(p_buffer, data1, datalen1);
		p_buffer += datalen1;
	}
	if (datalen2 > 0)
	{
		memcpy(p_buffer, data2, datalen2);
		p_buffer += datalen2;
	}
	if (datalen3 > 0)
	{
		memcpy(p_buffer, data3, datalen3);
		p_buffer += datalen3;
	}
	
	eccX08c_calculate_crc(len - ECCX08_CRC_SIZE, tx_buffer, p_buffer);
	
	// Send command and receive response.
	ret_code = eccX08c_send_and_receive(&tx_buffer[0], response_size,
		&rx_buffer[0],	poll_delay, poll_timeout);
		
	// Put device to sleep if command fails
	if (ret_code != ECCX08_SUCCESS)
		(void) eccX08p_sleep();
		
	return ret_code;
}
