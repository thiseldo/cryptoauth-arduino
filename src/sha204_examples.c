/** \file
 *  \brief  Application examples that Use the ATSHA204 Library
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
 *
*/

/** \defgroup atsha204_examples Module 12: Example Functions
<ul>
	<li>sha204e_checkmac_device:<br>
		Demonstrates communication using a MAC - CheckMac command sequence with
		relatively low security (mode 0: no Nonce), but little code space usage.
	</li>
	<li>
		sha204e_checkmac_firmware:<br>
		Demonstrates high security using a Nonce - GenDig - MAC command sequence
		and MAC verification in firmware. This requires more code space because
		a sha256 implementation in firmware is needed. Also, the firmware has to
		be able to access keys. Having a key stored outside the device poses a
		higher security risk.
	</li>
	<li>
		sha204e_checkmac_derive_key:<br>
		Demonstrates high security in a host / client scenario using a DeriveKey /
		MAC command sequence on one device (client) and a GenDig / CheckMac sequence
		on another device (host). No sha256 implementation in firmware is needed.
		All keys are only stored on the devices and never revealed. When using
		I<SUP>2</SUP>C you have to change the address of one of the devices first.
		Connect only one device to your CPU and use \ref sha204e_change_i2c_address
		to change it.<br>
		This example needs modifications introducing the Pause command when using
		the SWI UART interface.
	</li>
	<li>
		sha204e_checkmac_diversify_key:<br>
		Demonstrates high security in a host / client scenario using a
		Read / MAC command sequence on one device (client) and a GenDig / CheckMac
		sequence on another device (host). The MAC command uses a key id for a key
		that was diversified from the serial number of the client.
		No sha256 implementation in firmware is needed.
		All keys are only stored on the devices and never revealed. When using
		I<SUP>2</SUP>C you have to change the address of one of the devices first.
		Connect only one device to your CPU and use \ref sha204e_change_i2c_address
		to change it.<br>
		This example needs modifications introducing the Pause command when using
		the SWI UART interface.
	</li>
	<li>
		sha204e_change_i2c_address:<br>
		This is a utility function that changes the I<SUP>2</SUP>C address of a device so that
		you can run the \ref sha204e_checkmac_derived_key example when using I<SUP>2</SUP>C.
		Make sure that you don't have more than one device with the same address
		sitting on the bus.
	</li>
	<li>
		sha204e_read_config_zone:<br>
		This function reads all 88 bytes from the configuration zone. Since it does
		not depend on how the device is personalized or the lock status of the device,
		it is a good starting point to work with the library.
	</li>
</ul>

The example functions for SHA204_EXAMPLE_CHECKMAC_DEVICE and
SHA204_EXAMPLE_CHECKMAC_FIRMWARE use the sha204m_execute function that can be used
to send any ATSHA204 command. The other example functions use sha204m_... command wrapper
functions. Using only the sha204m_execute function in your application might compile into
smaller code size compared to using the command wrapper functions. You can use any
approach, but if you use the wrapper functions make sure you allow the compiler and linker
to garbage collect functions or remove unused functions manually to keep code size to a
minimum.

Examples that use an ATSHA204 as host you can run conveniently on an AT88CK109STK3
("Microbase" with 3-pin "Javan" kit, SWI). When using I<SUP>2</SUP>C, you can use the
AT88CK109STK8 version ("Microbase" with 8-pin "Javan" kit), but you have to change
the default I<SUP>2</SUP> address of one of the two devices first.

CAUTION WHEN DEBUGGING: Be aware of the timeout feature of the device. The
device will go to sleep between 0.7 and 1.7 seconds after a Wakeup. This timeout
cannot be re-started by any means. It only starts after a Wakeup pulse while the
device is in Idle or Sleep mode. When hitting a break point, this timeout will kick in
and the device has gone to sleep before you continue debugging. Therefore, after you have
examined variables you have to restart your debug session if the device was awake at
that point.
@{ */

#include <string.h>                   // needed for memset(), memcpy()
#include "sha204_lib_return_codes.h"  // declarations of function return codes
#include "sha204_comm_marshaling.h"   // definitions and declarations for the Command Marshaling module
#include "sha204_helper.h"            // definitions of functions that calculate SHA256 for every command
#include "sha204_examples.h"          // definitions and declarations for example functions


/** \brief key values at time of shipping
*/
const uint8_t sha204_default_key[16][SHA204_KEY_SIZE] = {
	{
		0x00, 0x00, 0x00, 0x0A, 0xA1, 0x1A, 0xAC, 0xC5, 0x57, 0x7F, 0xFF, 0xF4, 0x40, 0x04, 0x4E, 0xE4,
		0x45, 0x5D, 0xD4, 0x40, 0x04, 0x40, 0x01, 0x1B, 0xBD, 0xD0, 0x0E, 0xED, 0xD3, 0x3C, 0xC6, 0x67,
	},
	{
		0x11, 0x11, 0x11, 0x12, 0x23, 0x3B, 0xB6, 0x6C, 0xCC, 0xC5, 0x53, 0x3B, 0xB7, 0x7B, 0xB9, 0x9E,
		0xE9, 0x9B, 0xBB, 0xB5, 0x51, 0x1F, 0xFD, 0xD2, 0x2F, 0xF7, 0x74, 0x4C, 0xCD, 0xD0, 0x0E, 0xE9,
	},
	{
		0x22, 0x22, 0x22, 0x2C, 0xC1, 0x17, 0x7C, 0xC1, 0x1C, 0xC4, 0x4D, 0xD5, 0x56, 0x68, 0x89, 0x9A,
		0xAA, 0xA0, 0x00, 0x04, 0x43, 0x3E, 0xE3, 0x39, 0x9C, 0xCF, 0xFB, 0xB6, 0x6B, 0xB0, 0x0B, 0xB6,
	},
	{
		0x33, 0x33, 0x33, 0x33, 0x33, 0x36, 0x61, 0x14, 0x4A, 0xA1, 0x17, 0x79, 0x9A, 0xA2, 0x23, 0x36,
		0x6C, 0xC7, 0x7F, 0xFE, 0xE4, 0x4B, 0xBE, 0xE2, 0x2F, 0xF1, 0x13, 0x32, 0x20, 0x06, 0x67, 0x79,
	},
	{
		0x44, 0x44, 0x44, 0x49, 0x91, 0x11, 0x18, 0x86, 0x68, 0x83, 0x3D, 0xDB, 0xB8, 0x8D, 0xD3, 0x3F,
		0xF8, 0x85, 0x57, 0x70, 0x0C, 0xC7, 0x74, 0x42, 0x2E, 0xED, 0xDA, 0xAD, 0xDA, 0xA5, 0x52, 0x28,
	},
	{
		0x55, 0x55, 0x55, 0x58, 0x86, 0x6F, 0xF2, 0x2B, 0xB3, 0x32, 0x20, 0x09, 0x98, 0x8A, 0xA6, 0x6E,
		0xE1, 0x1E, 0xE6, 0x63, 0x33, 0x37, 0x7A, 0xA5, 0x52, 0x20, 0x01, 0x10, 0x03, 0x36, 0x6A, 0xA0,
	},
	{
		0x66, 0x66, 0x66, 0x6D, 0xD0, 0x04, 0x45, 0x53, 0x3A, 0xAC, 0xC2, 0x22, 0x25, 0x55, 0x57, 0x7F,
		0xF6, 0x6D, 0xD4, 0x46, 0x6B, 0xB7, 0x7D, 0xDD, 0xDF, 0xF9, 0x96, 0x68, 0x89, 0x9D, 0xDA, 0xA2,
	},
	{
		0x77, 0x77, 0x77, 0x72, 0x2F, 0xF4, 0x4A, 0xA9, 0x9C, 0xCC, 0xC0, 0x05, 0x5E, 0xE4, 0x45, 0x59,
		0x99, 0x9B, 0xBD, 0xD2, 0x26, 0x69, 0x96, 0x6D, 0xDD, 0xD4, 0x49, 0x9F, 0xF8, 0x8A, 0xA5, 0x50,
	},
	{
		0x88, 0x88, 0x88, 0x8C, 0xC6, 0x62, 0x2A, 0xAF, 0xFE, 0xE1, 0x1F, 0xF8, 0x82, 0x2D, 0xD4, 0x4E,
		0xE0, 0x08, 0x85, 0x58, 0x85, 0x53, 0x34, 0x44, 0x4D, 0xD7, 0x77, 0x7B, 0xB8, 0x89, 0x9D, 0xDE,
	},
	{
		0x99, 0x99, 0x99, 0x94, 0x4E, 0xE6, 0x6D, 0xD4, 0x4A, 0xAF, 0xF5, 0x59, 0x92, 0x23, 0x30, 0x06,
		0x6B, 0xBD, 0xD2, 0x2D, 0xD5, 0x52, 0x27, 0x77, 0x7D, 0xD7, 0x77, 0x7B, 0xB3, 0x39, 0x95, 0x5E,
	},
	{
		0xAA, 0xAA, 0xAA, 0xA1, 0x15, 0x5A, 0xA2, 0x25, 0x55, 0x50, 0x0B, 0xBD, 0xD2, 0x2E, 0xEA, 0xA9,
		0x9A, 0xAF, 0xF2, 0x29, 0x96, 0x64, 0x46, 0x61, 0x15, 0x56, 0x69, 0x91, 0x11, 0x11, 0x12, 0x29,
	},
	{
		0xBB, 0xBB, 0xBB, 0xB2, 0x24, 0x4D, 0xDB, 0xB7, 0x78, 0x8A, 0xA8, 0x87, 0x70, 0x06, 0x64, 0x4A,
		0xA1, 0x1F, 0xF0, 0x08, 0x8D, 0xDC, 0xC9, 0x91, 0x17, 0x79, 0x96, 0x66, 0x60, 0x00, 0x0A, 0xAF,
	},
	{
		0xCC, 0xCC, 0xCC, 0xCC, 0xC6, 0x61, 0x17, 0x71, 0x1A, 0xA5, 0x52, 0x24, 0x45, 0x5A, 0xAC, 0xCD,
		0xD2, 0x29, 0x92, 0x24, 0x46, 0x62, 0x28, 0x89, 0x90, 0x06, 0x62, 0x24, 0x4C, 0xCA, 0xA5, 0x56,
	},
	{
		0xDD, 0xDD, 0xDD, 0xDB, 0xBF, 0xFA, 0xAC, 0xC1, 0x11, 0x17, 0x70, 0x05, 0x55, 0x59, 0x9C, 0xCC,
		0xC9, 0x9B, 0xB6, 0x62, 0x28, 0x80, 0x0F, 0xF9, 0x92, 0x29, 0x95, 0x5D, 0xDF, 0xF3, 0x30, 0x00,
	},
	{
		0xEE, 0xEE, 0xEE, 0xE0, 0x08, 0x85, 0x55, 0x57, 0x77, 0x7B, 0xBD, 0xDA, 0xA7, 0x7B, 0xB8, 0x8A,
		0xA7, 0x7A, 0xAF, 0xF5, 0x58, 0x8D, 0xD1, 0x18, 0x8B, 0xB9, 0x92, 0x2F, 0xF0, 0x0D, 0xDF, 0xF7,
	},
	{
		0xFF, 0xFF, 0xFF, 0xF6, 0x68, 0x8B, 0xB7, 0x7B, 0xB8, 0x80, 0x01, 0x1B, 0xBE, 0xE6, 0x66, 0x62,
		0x2C, 0xCE, 0xEC, 0xC7, 0x74, 0x46, 0x68, 0x80, 0x0F, 0xFE, 0xE4, 0x47, 0x7D, 0xDC, 0xC1, 0x1C,
	},
};


/** 
 * \brief This function wraps \ref sha204p_sleep().
 *
 *        It puts both devices to sleep if two devices (client and host) are used.
 *        This function is also called when a Wakeup did not succeed. 
 *        This would not make sense if a device did not wakeup and it is the only
 *        device on SDA, but if there are two devices (client and host) that
 *        share SDA, the device that is not selected has also woken up.
 */
void sha204e_sleep() 
{
#if defined(SHA204_I2C) && (SHA204_CLIENT_ADDRESS != SHA204_HOST_ADDRESS)
	// Select host device...
	sha204p_set_device_id(SHA204_HOST_ADDRESS);
	// and put it to sleep.
	(void) sha204p_sleep();
	// Select client device...
	sha204p_set_device_id(SHA204_CLIENT_ADDRESS);
	// and put it to sleep.
	(void) sha204p_sleep();
#else	
	(void) sha204p_sleep();
#endif
}


/** \brief This function wakes up two I<SUP>2</SUP>C devices and puts one back to
           sleep, effectively waking up only one device among two that share the bus.
	\param[in] device_id which device to wake up
	\return status of the operation
*/
uint8_t sha204e_wakeup_device(uint8_t device_id)
{
	uint8_t ret_code;
	uint8_t wakeup_response[SHA204_RSP_SIZE_MIN];

	sha204p_set_device_id(device_id);

	// Wake up the devices.
	memset(wakeup_response, 0, sizeof(wakeup_response));
	ret_code = sha204c_wakeup(wakeup_response);
	if (ret_code != SHA204_SUCCESS) {
		sha204e_sleep();
		return ret_code;
	}

#if defined(SHA204_I2C) && (SHA204_CLIENT_ADDRESS != SHA204_HOST_ADDRESS)
	// SHA204 I2C devices can share SDA. We have to put the other device back to sleep.
	// Select other device...
	sha204p_set_device_id(device_id == SHA204_CLIENT_ADDRESS ? SHA204_HOST_ADDRESS : SHA204_CLIENT_ADDRESS);
	// and put it to sleep.
	ret_code = sha204p_sleep();
	
	// Now select the device we want to communicate with.
	sha204p_set_device_id(device_id);
#endif

	return ret_code;	
}


/** \brief This function checks the response status byte and puts the device
           to sleep if there was an error.
   \param[in] ret_code return code of function
	\param[in] response pointer to response buffer
	\return status of the operation
*/
uint8_t sha204e_check_response_status(uint8_t ret_code, uint8_t *response)
{
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}
	ret_code = response[SHA204_BUFFER_POS_STATUS];
	if (ret_code != SHA204_SUCCESS)
		sha204p_sleep();

	return ret_code;	
}


/** \brief This function reads the serial number from the device.
 *
           The serial number is stored in bytes 0 to 3 and 8 to 12
           of the configuration zone.
   \param[in] tx_buffer pointer to transmit buffer.
	\param[out] sn pointer to nine-byte serial number
	\return status of the operation
*/
uint8_t sha204e_read_serial_number(uint8_t *tx_buffer, uint8_t *sn)
{
	uint8_t rx_buffer[READ_32_RSP_SIZE];
	
	uint8_t status = sha204m_read(tx_buffer, rx_buffer, 
						SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_CONFIG, 0);
	if (status != SHA204_SUCCESS)
		sha204p_sleep();
	
	memcpy(sn, &rx_buffer[SHA204_BUFFER_POS_DATA], 4);
	memcpy(sn + 4, &rx_buffer[SHA204_BUFFER_POS_DATA + 8], 5);
	
	return status;
}


/** \brief This function locks the configuration zone.
    
	It first reads it and calculates the CRC of its content.
	It then sends a Lock command to the device.
	
	This function is disabled by default with the
	\ref SHA204_EXAMPLE_CONFIG_WITH_LOCK switch.

	Once the configuration zone is locked, the Random
	command returns a number from its high quality random
	number generator instead of a 0xFFFF0000FFFF0000...
	sequence.

	\param[in] device_id which device to lock
	\return status of the operation
*/
uint8_t sha204e_lock_config_zone(uint8_t device_id)
{
	uint8_t ret_code;
	uint8_t config_data[SHA204_CONFIG_SIZE];
	uint8_t crc_array[SHA204_CRC_SIZE];
	uint16_t crc;
	uint8_t command[LOCK_COUNT];
	uint8_t response[LOCK_RSP_SIZE];
	
	sha204p_sleep();
	
	ret_code = sha204e_read_config_zone(device_id, config_data);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;
		
	// Check whether the configuration zone is locked already.
	if (config_data[87] == 0)
		return ret_code;
	
	sha204c_calculate_crc(sizeof(config_data), config_data, crc_array);
	crc = (crc_array[1] << 8) + crc_array[0];

	ret_code = sha204c_wakeup(response);
	ret_code = sha204m_lock(command, response, SHA204_ZONE_CONFIG, crc);
	
	return ret_code;
}


/** \brief This function configures a child and parent key for derived key scenarios.
 *
 *         To run this scenario successfully the client device has
 *         to be configured first: We use a key slot in the client device that is already
 *         configured for this purpose, but we need to point to a parent whose
 *         CheckOnly flag is set on the host device. On the client device we have
 *         to reset this bit, otherwise the DeriveKey command would return an error.
 *         Key id 10 is chosen for the child key because only its parent key needs to be changed
 *         from its default configuration. Key id 13 is chosen for the parent key because only
 *         its CheckOnly flag has to be reset compared to its default configuration.
    \return status of the operation
*/
uint8_t sha204e_configure_key()
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;

	const uint8_t config_child = 0x7D;
	const uint8_t config_parent = 0xCD;
	const uint8_t config_address = 32;
	
	// Make the command buffer the long size (32 bytes, no MAC) of the Write command.
	uint8_t command[WRITE_COUNT_LONG];
	
	uint8_t data_load[SHA204_ZONE_ACCESS_32];

	// Make the response buffer the size of a Read response.
	uint8_t response[READ_32_RSP_SIZE];

	// Wake up the client device.
	ret_code = sha204e_wakeup_device(SHA204_CLIENT_ADDRESS);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;
	
	// Read client device configuration for child key.
	memset(response, 0, sizeof(response));
	ret_code = sha204m_read(command, response, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_CONFIG, config_address);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}

	// Check whether we configured already. If so, exit here.
	if ((response[SHA204_BUFFER_POS_DATA + 9] == config_child)
		&& (response[SHA204_BUFFER_POS_DATA + 14] == config_parent)) {
		sha204p_sleep();
		return ret_code;
	}

	// Write client configuration.
	memcpy(data_load, &response[SHA204_BUFFER_POS_DATA], sizeof(data_load));
	data_load[9] = config_child;
	data_load[14] = config_parent;
	ret_code = sha204m_write(command, response, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_CONFIG,
							config_address, data_load, NULL);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}

	sha204p_sleep();
	
	return ret_code;
}


/** \brief This function configures the client for the derived key and
 *         diversified key example.
 *
 *         Creating a derived key allows a host device to check a MAC
 *         in a highly secure fashion. No replay attacks are possible
 *         and SHA256 calculation in firmware is not needed.
 * \return status of the operation
 */
uint8_t sha204e_configure_derive_key()
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;

	// Configure key.
	ret_code = sha204e_configure_key();
	if (ret_code != SHA204_SUCCESS)
		return ret_code;
	
#if (SHA204_EXAMPLE_CONFIG_WITH_LOCK != 0)
	ret_code = sha204e_lock_config_zone(SHA204_HOST_ADDRESS);
#endif

	return ret_code;
}


/** \brief This function configures a client device for the diversified key example.
 *
 *         After configuration is done, the diversified key is programmed with the following
 *         command sequence:
 *         - Read 9-byte serial number from configuration zone and pad it with 23 zeros.
 *         - Send the zero padded serial number with a Nonce command (mode = pass-through).
 *         - Send a DeriveKey command with the child identifier as the target.
 * \return status of the operation
 */
uint8_t sha204e_configure_diversify_key(void)
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;
	
	uint8_t command[NONCE_COUNT_LONG];
	uint8_t response[SHA204_RSP_SIZE_MIN];
	uint8_t data_load[NONCE_NUMIN_SIZE_PASSTHROUGH];

	// Configure key.
	ret_code = sha204e_configure_key();
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	// Wake up the client device.
	ret_code = sha204e_wakeup_device(SHA204_CLIENT_ADDRESS);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	// Read serial number and pad it.
	memset(data_load, 0, sizeof(data_load));
	ret_code = sha204e_read_serial_number(command, data_load);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}
	
	//  Put padded serial number into TempKey (fixed Nonce).
	ret_code = sha204m_nonce(command, response, NONCE_MODE_PASSTHROUGH, data_load);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}
	
	//  Send DeriveKey command.
	ret_code = sha204m_derive_key(command, response, DERIVE_KEY_RANDOM_FLAG, SHA204_KEY_CHILD, NULL);
	
#ifdef SHA204_EXAMPLE_CONFIG_WITH_LOCK
	sha204p_sleep();

	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	ret_code = sha204e_lock_config_zone(SHA204_HOST_ADDRESS);
#endif

	// Put client device to sleep.
	sha204p_sleep();
	
	return ret_code;
}


/** \brief This function serves as an authentication example 
 *         using the SHA204 MAC and CheckMac commands.
 *
 *         In an infinite loop, it issues the same command
 *         sequence using the sha204m_execute command of the
 *         Command Marshaling layer of the ATSHA204 library.

The command sequence wakes up the device, issues a MAC command in mode 0
using the Command Marshaling layer, puts the device to sleep, and verifies the MAC
(fixed challenge / response). Then it wakes up the same
(SHA204_CLIENT_ADDRESS == SHA204_HOST_ADDRESS) or a second device, issues
a CheckMac command supplying data obtained from the previous MAC command, verifies
the response status byte, and puts the device to sleep.
 * \return status of the operation
 */
uint8_t sha204e_checkmac_device(void)
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;

	uint8_t i;
	uint8_t comparison_result;
	
	// Make the command buffer the size of the CheckMac command.
	static uint8_t command[CHECKMAC_COUNT];

	// Make the response buffer the size of a MAC response.
	static uint8_t response_mac[MAC_RSP_SIZE];
	
	// First four bytes of Mac command are needed for CheckMac command.
	static uint8_t other_data[CHECKMAC_OTHER_DATA_SIZE];
	
	// CheckMac response buffer
	static uint8_t response_checkmac[CHECKMAC_RSP_SIZE];

   // expected MAC response in mode 0
	static const uint8_t mac_mode0_response_expected[MAC_RSP_SIZE] =
	{
		MAC_RSP_SIZE,                                   // count
		0x06, 0x67, 0x00, 0x4F, 0x28, 0x4D, 0x6E, 0x98,
		0x62, 0x04, 0xF4, 0x60, 0xA3, 0xE8, 0x75, 0x8A,
		0x59, 0x85, 0xA6, 0x79, 0x96, 0xC4, 0x8A, 0x88,
		0x46, 0x43, 0x4E, 0xB3, 0xDB, 0x58, 0xA4, 0xFB,
		0xE5, 0x73                                       // CRC
	};

	// data for challenge in MAC mode 0 command
	const uint8_t challenge[MAC_CHALLENGE_SIZE] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
	};

	// Initialize the hardware interface.
	// Depending on which interface you have linked the
	// library to, it initializes SWI UART, SWI GPIO, or I2C.
	sha204p_init();

	while (1) {
		// If you put a break point here you will see the last
		// status response after every iteration.
		// 0x04 0x00 0x03 0x40 indicates that the last command succeeded
		// which is the CheckMac command.
		ret_code = sha204e_wakeup_device(SHA204_CLIENT_ADDRESS);
		if (ret_code != SHA204_SUCCESS)
			return ret_code;

		// Mac command with mode = 0.
		memset(response_mac, 0, sizeof(response_mac));
		ret_code = sha204m_execute(SHA204_MAC, MAC_MODE_CHALLENGE, SHA204_KEY_ID, sizeof(challenge), (uint8_t *) challenge,
					0, NULL, 0, NULL, sizeof(command), command, sizeof(response_mac), response_mac);
		// Put client device to sleep.
		sha204p_sleep();
		if (ret_code != SHA204_SUCCESS)
			continue;

		// Compare returned MAC with expected one. 
		// Make this loop resistant against a timing attack.
		comparison_result = 0;
		for (i = 0; i < sizeof(response_mac); i++)
			comparison_result |= (response_mac[i] ^ mac_mode0_response_expected[i]);
		ret_code = (comparison_result ? SHA204_GEN_FAIL : SHA204_SUCCESS);

		// Now check the MAC using the CheckMac command.
		// Put a break point below if you like to see the result of the comparison above.
		ret_code = sha204e_wakeup_device(SHA204_HOST_ADDRESS);
		if (ret_code != SHA204_SUCCESS)
			return ret_code;

		// CheckMac command with mode = 0.
		// Use the wakeup_response buffer for the CheckMac response.
		memset(response_checkmac, 0, sizeof(response_checkmac));
		// Copy Mac command byte 1 to 5 (op-code, param1, param2) to other_data.
		memcpy(other_data, &command[SHA204_OPCODE_IDX], CHECKMAC_CLIENT_COMMAND_SIZE);
		// Set the remaining nine bytes of other_data to 0.
		memset(&other_data[CHECKMAC_CLIENT_COMMAND_SIZE - 1], 0, sizeof(other_data) - CHECKMAC_CLIENT_COMMAND_SIZE);
		ret_code = sha204m_execute(
					SHA204_CHECKMAC, CHECKMAC_MODE_CHALLENGE, SHA204_KEY_ID, 
					sizeof(challenge), (uint8_t *) challenge, 
					CHECKMAC_CLIENT_RESPONSE_SIZE, &response_mac[SHA204_BUFFER_POS_DATA], 
					sizeof(other_data), other_data, 
					sizeof(command), command, sizeof(response_checkmac), response_checkmac);

		// Put host device to sleep. Put a breakpoint here to inspect the CheckMac response.
		sha204p_sleep();
		
		// Status byte = 0 means success. This line serves only a debug purpose.
		// For newer GCC's, this is not a safe spot to put a break point.
		ret_code = sha204e_check_response_status(ret_code, response_checkmac);
	}

	return ret_code;
}


/** \brief This function serves as an authentication example
 *         using the SHA204 Nonce, GenDig, and MAC commands.
 *
 *         In an infinite loop, it issues the same command
 *         sequence using the Command Marshaling layer of
 *         the ATSHA204 library.

The following command sequence wakes up the device, issues a Nonce, a GenDig, and
a MAC command using the Command Marshaling layer, and puts the device to sleep.
In parallel, it calculates in firmware the TempKey and the MAC using helper
functions located in \ref sha204_helper.c and compares the MAC command response
with the calculated result.
 * \return status of the operation
 */
uint8_t sha204e_checkmac_firmware(void)
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;
	uint8_t i;
	uint8_t comparison_result;
	uint8_t mac_mode = MAC_MODE_BLOCK1_TEMPKEY | MAC_MODE_BLOCK2_TEMPKEY;
	struct sha204h_nonce_in_out nonce_param;	   //parameter for nonce helper function
	struct sha204h_gen_dig_in_out gendig_param;	//parameter for gendig helper function
	struct sha204h_mac_in_out mac_param;		   //parameter for mac helper function
	struct sha204h_temp_key tempkey;			      //tempkey parameter for nonce and mac helper function
	static uint8_t wakeup_response[SHA204_RSP_SIZE_MIN];
	static uint8_t tx_buffer[CHECKMAC_COUNT];
	static uint8_t rx_buffer[MAC_RSP_SIZE];
	static uint8_t mac[CHECKMAC_CLIENT_RESPONSE_SIZE];
	uint8_t num_in[NONCE_NUMIN_SIZE] = {
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x30, 0x31, 0x32, 0x33
	};
	uint8_t key_slot_0[SHA204_KEY_SIZE] = {
		0x00, 0x00, 0xA1, 0xAC, 0x57, 0xFF, 0x40, 0x4E,
		0x45, 0xD4,	0x04, 0x01, 0xBD, 0x0E, 0xD3, 0xC6,
		0x73, 0xD3, 0xB7, 0xB8,	0x2D, 0x85, 0xD9, 0xF3,
		0x13, 0xB5, 0x5E, 0xDA, 0x3D, 0x94,	0x00, 0x00
	};

	// Initialize the hardware interface.
	// Depending on which interface you have linked the
	// library to, it initializes SWI UART, SWI GPIO, or I2C.
	sha204p_init();

	while (1) {
		// ----------------------- Nonce --------------------------------------------
		// Wake up the device.
		// If you put a break point here you will see the last
		// status after every iteration.
		// You can also inspect the mac and rx_buffer variables which should match.
		memset(wakeup_response, 0, sizeof(wakeup_response));
		ret_code = sha204c_wakeup(wakeup_response);
		if (ret_code != SHA204_SUCCESS) {
			(void) sha204p_sleep();
			continue;
		}			
	
		// Issue a Nonce command. When the configuration zone of the device is not locked the 
		// random number returned is a constant 0xFFFF0000FFFF0000...
		memset(rx_buffer, 0, sizeof(rx_buffer));
		ret_code = sha204m_execute(SHA204_NONCE, NONCE_MODE_NO_SEED_UPDATE, 0, NONCE_NUMIN_SIZE, num_in, 
			0, NULL, 0, NULL, sizeof(tx_buffer), tx_buffer, sizeof(rx_buffer), rx_buffer);
		if (ret_code != SHA204_SUCCESS) {
			(void) sha204p_sleep();
			continue;
		}

		// Put device into Idle mode since the TempKey calculation in firmware might take longer
		// than the device timeout. Putting the device into Idle instead of Sleep mode
		// maintains the TempKey.
		sha204p_idle();
		
		// Calculate TempKey using helper function.
		nonce_param.mode = NONCE_MODE_NO_SEED_UPDATE;
		nonce_param.num_in = num_in;	
		nonce_param.rand_out = &rx_buffer[SHA204_BUFFER_POS_DATA];	
		nonce_param.temp_key = &tempkey;
		ret_code = sha204h_nonce(&nonce_param);
		if (ret_code != SHA204_SUCCESS) {
			sha204e_wakeup_sleep();
			continue;
		}

		// ----------------------- GenDig --------------------------------------------
		// Wake up the device from Idle mode.
		memset(wakeup_response, 0, sizeof(wakeup_response));
		ret_code = sha204c_wakeup(wakeup_response);
		if (ret_code != SHA204_SUCCESS) {
			(void) sha204p_sleep();
			continue;
		}			

		memset(rx_buffer, 0, sizeof(rx_buffer));
		ret_code = sha204m_execute(SHA204_GENDIG, GENDIG_ZONE_DATA, SHA204_KEY_ID, 0,
			NULL, 0, NULL, 0, NULL, sizeof(tx_buffer), tx_buffer, sizeof(rx_buffer), rx_buffer);		 
		if (ret_code != SHA204_SUCCESS) {
			(void) sha204p_sleep();
			continue;
		}
		// Check response status byte for error.
		if (rx_buffer[SHA204_BUFFER_POS_STATUS] != SHA204_SUCCESS) {
			(void) sha204p_sleep();
			continue;
		}
		sha204p_idle();

		// Update TempKey using helper function.
		gendig_param.zone = GENDIG_ZONE_DATA;
		gendig_param.key_id = SHA204_KEY_ID;
		gendig_param.stored_value = key_slot_0;
		gendig_param.temp_key = &tempkey;
		ret_code = sha204h_gen_dig(&gendig_param);
		if (ret_code != SHA204_SUCCESS) {
			sha204e_wakeup_sleep();
			continue;
		}

		// ----------------------- MAC --------------------------------------------
		// Wake up the device from Idle mode.
		memset(wakeup_response, 0, sizeof(wakeup_response));
		ret_code = sha204c_wakeup(wakeup_response);
		if (ret_code != SHA204_SUCCESS) {
			(void) sha204p_sleep();
			continue;
		}
		
		// Issue a MAC command with mode = 3.
		memset(rx_buffer, 0, sizeof(rx_buffer));
		ret_code = sha204m_execute(SHA204_MAC, mac_mode, SHA204_KEY_ID,
			0, NULL, 0, NULL, 0, NULL, sizeof(tx_buffer), tx_buffer, sizeof(rx_buffer), rx_buffer);		 

		// Put device to sleep.
		sha204p_sleep();

		if (ret_code != SHA204_SUCCESS)
			continue;
		
		// Calculate MAC using helper function.
		mac_param.mode = mac_mode;
		mac_param.key_id = SHA204_KEY_ID;
		mac_param.challenge = NULL;
		mac_param.key = NULL;
		mac_param.otp = NULL;
		mac_param.sn = NULL;
		mac_param.response = mac;
		mac_param.temp_key = &tempkey;
		ret_code = sha204h_mac(&mac_param);
		if (ret_code != SHA204_SUCCESS)
			continue;
		
		// Compare the Mac response with the calculated MAC.
		// Make this loop resistant against a timing attack.
		comparison_result = 0;
		for (i = 0; i < sizeof(mac); i++)
			comparison_result |= (rx_buffer[i + SHA204_BUFFER_POS_STATUS] ^ mac[i]);

		ret_code = (comparison_result ? SHA204_GEN_FAIL : SHA204_SUCCESS);
	}

	return ret_code;
}


/** \brief This function serves as an authentication example using the SHA204 Nonce,
 *         DeriveKey, and MAC commands for a client, and the Nonce, GenDig, and
 *         CheckMac commands for a host device.

Creating a child key on the client allows a host device to check a MAC in a highly secure
fashion. No replay attacks are possible when using a random number generated by the host
device as the challenge, SHA256 calculation in firmware is not needed, and keys are only
stored on the secure device.
 
A brief explanation for this command sequence:
The client generates a child key (DeriveKey command) derived from a parent key that it
shares with the host device, using a random nonce (commands Random and Nonce). It then
stores it in one of its key slots. The host generates the same key and stores it in its
TempKey using the same nonce. Now, when the client receives a MAC command with the child
key id, a CheckMac command on the host using the TempKey will succeed.

To run this command sequence successfully the devices have to be configured first: 
The child key has to point to the parent, and the parent key in the host device has to be
flagged as CheckOnly.

Because every time this command sequence is executed the slot for the child key is being 
written, this sequence does not run in a loop to prevent wearing out the flash.

Command sequence when using a derived key:
<ol>
<li>
	MCU to client device: fixed nonce -> TempKey
</li>
<li>
	MCU to client device: DeriveKey -> 
	child key in chosen slot (child key configuration points to parent key)
</li>
<li>
	MCU to client device: fixed nonce -> TempKey</li>
<li>
	MCU to client device: MAC -> 
	response = sha256(chosen slot  / child key, fixed nonce / TempKey, 
	                  command, 3 bytes of SN)
</li>
<li>
	MCU to host device:   GenDig -> TempKey = child key
</li>
<li>
	MCU to host device:   CheckMac -> 
	sha256(child key / TempKey, challenge / fixed nonce, MAC command, 3 bytes of SN)
</li>
</ol>
As you can see, the sha256 input values for the MAC and the CheckMac commands are the
same (child key, fixed nonce, MAC command, the three constant bytes of SN).


 * \return status of the operation
 */
uint8_t sha204e_checkmac_derived_key(void)
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;

	static uint8_t response_random[RANDOM_RSP_SIZE];
	uint8_t *random = &response_random[SHA204_BUFFER_POS_DATA];
	
	// Make the command buffer the minimum size of the Write command.
	uint8_t command[SHA204_CMD_SIZE_MAX];

	// Make the response buffer the maximum size.
	uint8_t response_status[SHA204_RSP_SIZE_MIN];

	// MAC response buffer
	uint8_t response_mac[SHA204_RSP_SIZE_MAX];
	
	// We need this buffer for the DeriveKey, GenDig, and CheckMac command.
	uint8_t other_data[CHECKMAC_OTHER_DATA_SIZE];
	
	uint8_t command_derive_key[GENDIG_OTHER_DATA_SIZE];
	
	uint8_t command_mac[CHECKMAC_CLIENT_COMMAND_SIZE];
		
	// Initialize the hardware interface.
	// Depending on which interface you have linked the
	// library to, it initializes SWI GPIO, or I2C.
	// This example does not run when SWI UART is used.
	sha204p_init();

	ret_code = sha204e_configure_derive_key();
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	ret_code = sha204c_wakeup(response_status);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;
	
	/*
	Obtain a random number from host device. We can generate a random number to
	be used by a pass-through nonce (TempKey.SourceFlag = Input = 1) in whatever 
	way we want but we use the host	device because it has a high-quality random 
	number generator. We are using the host and not the client device because we 
	like to show a typical accessory authentication example where the MCU this 
	code is running on and the host device are inaccessible to an adversary, 
	whereas the client device is built into an easily accessible accessory. We 
	prevent an adversary to	mount replay attacks by supplying the pass-through
	nonce. For the same reason, we do not want to use the same pass-through 
	number every time we authenticate. The same nonce would produce the same Mac 
	response. Be aware that the Random command returns a fixed number
	(0xFFFF0000FFFF0000...) when the configuration zone of the device is not locked.
	*/
	
	sha204p_set_device_id(SHA204_HOST_ADDRESS);

	// ---------------------------------------------------------------------------
	// host: Get random number.
	// No need to update the seed because it gets updated with every wake / sleep
	// cycle anyway.
	// ---------------------------------------------------------------------------
	ret_code = sha204m_random(command, response_random, RANDOM_NO_SEED_UPDATE);
	if (ret_code != SHA204_SUCCESS) {
		sha204e_sleep();
		return ret_code;
	}
	
	// ---------------------------------------------------------------------------
	// client: Create child key using a random pass-through nonce. 
	// Then send a MAC command using the same nonce.
	// ---------------------------------------------------------------------------
	sha204p_set_device_id(SHA204_CLIENT_ADDRESS);

	// Send Nonce command in pass-through mode using the random number in preparation
	// for DeriveKey command. TempKey holds the random number after this command succeeded.
	ret_code = sha204m_nonce(command, response_status, NONCE_MODE_PASSTHROUGH, random);
	if (ret_code != SHA204_SUCCESS) {
		sha204e_sleep();
		return ret_code;
	}

	// Send DeriveKey command.
	// child key = sha256(parent key[32], DeriveKey command[4], sn[3], 0[25], TempKey[32] = random)
	ret_code = sha204m_derive_key(command, response_status, DERIVE_KEY_RANDOM_FLAG, SHA204_KEY_CHILD, NULL);
	if (ret_code != SHA204_SUCCESS) {
		sha204e_sleep();
		return ret_code;
	}
	
	// Copy op-code and parameters to command_derive_key to be used in subsequent GenDig and CheckMac
	// host commands.
	memcpy(command_derive_key, &command[SHA204_OPCODE_IDX], sizeof(command_derive_key));

	// Send Nonce command in preparation for MAC command.
	ret_code = sha204m_nonce(command, response_status, NONCE_MODE_PASSTHROUGH, random);
	if (ret_code != SHA204_SUCCESS) {
		sha204e_sleep();
		return ret_code;
	}

	// Send MAC command.
	// MAC = sha256(child key[32], TempKey[32] = random, MAC command[4], 0[11], sn8[1], 0[4], sn0_1[2], 0[2])
	// mode: first 32 bytes data slot (= child key), second 32 bytes TempKey (= random), TempKey.SourceFlag = Input
	ret_code = sha204m_mac(command, response_mac, MAC_MODE_BLOCK2_TEMPKEY | MAC_MODE_SOURCE_FLAG_MATCH, 
	                       SHA204_KEY_CHILD, NULL);
	if (ret_code != SHA204_SUCCESS) {
		sha204e_sleep();
		return ret_code;
	}

	// Save op-code and parameters to be used in the CheckMac command for the host.
	memcpy(command_mac, &command[SHA204_OPCODE_IDX], sizeof(command_mac));
		
	// Put client device to sleep.
	sha204p_sleep();
	
	// ---------------------------------------------------------------------------
	// host: Generate digest (GenDig) using a random pass-through nonce.
	// Then send a CheckMac command with the MAC response.
	// ---------------------------------------------------------------------------

	// Send Nonce command in pass-through mode using the random number in preparation
	// for GenDig command. TempKey holds the random number after this command succeeded.
	sha204p_set_device_id(SHA204_HOST_ADDRESS);
	ret_code = sha204m_nonce(command, response_status, NONCE_MODE_PASSTHROUGH, random);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}

	// Send GenDig command. TempKey holds the child key of the client after this command succeeded.
	// TempKey (= child key) = sha256(parent key[32], DeriveKey command[4], sn[3], 0[25], TempKey[32] = random)
	ret_code = sha204m_gen_dig(command, response_status, GENDIG_ZONE_DATA, SHA204_KEY_PARENT, command_derive_key);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}
		
	// Send CheckMac command.
	// CheckMac = sha256(TempKey[32] = child key, random[32], Mac command[4], 0[11], sn8[1], 0[4], sn0_1[2], 0[2])
	// mode: first 32 bytes TempKey (= child key), second 32 bytes client challenge (= random), TempKey.SourceFlag = Input
	// TempKey = child key -> CheckMac = MAC
	// Copy MAC command bytes (op-code, param1, param2) to other_data.
	memset(other_data, 0, sizeof(other_data));
	memcpy(other_data, command_mac, sizeof(command_mac));
	ret_code = sha204m_check_mac(command, response_status, CHECKMAC_MODE_BLOCK1_TEMPKEY | CHECKMAC_MODE_SOURCE_FLAG_MATCH, 
	                             0, random, &response_mac[SHA204_BUFFER_POS_DATA], other_data);
	sha204p_sleep();
	
	ret_code = sha204e_check_response_status(ret_code, response_status);

	return ret_code;
}


/** \brief This function serves as an authentication example using the ATSHA204 Read and
 *         MAC commands for a client, and the Nonce, GenDig, and CheckMac commands for
 *         a host device.

Creating a diversified key on the client using its serial number allows a host device to
check a MAC using a root key on devices with different diversified keys. The host device
can calculate the diversified key by using a root key and the serial number of the client.

Brief explanation for this command sequence:\n
During personalization, a key is derived from a root key residing in the host, and the
serial number of the client. The host reads the serial number of the client, pads it with
zeros, and stores it in its TempKey. It then executes a GenDig command that hashes the
root key and the TempKey, a.o. Now, when the client receives a MAC command with the 
child key id, a CheckMac command on the host using the TempKey will succeed.

To run this command sequence successfully the host device has to be configured first: 
The parent key has to be flagged as CheckOnly and the child key has to point to the parent key.

Use the following sequence for secure authentication using the default configuration for
the host device and modifying the default configuration for the client. (This function does
this for you by calling \ref sha204e_configure_diversify_key.)
<ul>
<li>
	Point slot 10 (child key) to key id 13 (parent key) by changing the default from 0x7A
	(parent key = 10, roll key operation) to 0x7D (parent key = 13).
</li>
<li>
	Reset the CheckOnly flag in key 13 by changing the default from 0xDD to 0xCD.
</li>
</ul>

Command sequence when using a diversified key:
<ol>
<li>
	MCU to client device: Read serial number (Read command, zone = config, address = 0).
</li>
<li>
	MCU to host device:   Get random number (Random command).
</li>
<li>
	MCU to host device:   Pad serial number with zeros and store it in TempKey 
	                      (Nonce command, mode = pass-through).
</li>
<li>
	MCU to host device:   GenDig -> Host TempKey now holds child key 
	                                (GenDig command, other data = DeriveKey command).
</li>
<li>
	MCU to client device: MAC -> 
	response = sha256(child key, challenge = random, MAC command, 3 bytes of SN)
</li>
<li>
	MCU to host device:   CheckMac -> 
	sha256(TempKey = child key, challenge = random = provided, MAC command, 3 bytes of SN)
</li>
</ol>

 * \return status of the operation
 */
uint8_t sha204e_checkmac_diversified_key(void)
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;

	// Make the command buffer the maximum command size.
	uint8_t command[SHA204_CMD_SIZE_MAX];

	// padded serial number (9 bytes + 23 zeros)
	uint8_t serial_number[NONCE_NUMIN_SIZE_PASSTHROUGH];

	// random number - is used as the MAC challenge
	uint8_t response_random[RANDOM_RSP_SIZE];
	uint8_t *random_number = &response_random[SHA204_BUFFER_POS_DATA];

	// DeriveKey command.
	// This command was used during configuration (personalization) to 
	// diversify the root key with the serial number of the client.
	uint8_t derive_key_command[] = {0x1C, 0x04, 0x0A, 0x00};
	
	// Make the status response buffer the size of a status response.
	uint8_t response_status[SHA204_RSP_SIZE_MIN];

	// MAC response buffer
	uint8_t response_mac[SHA204_RSP_SIZE_MAX];
	
	// We need this buffer for the CheckMac command.
	uint8_t checkmac_other_data[CHECKMAC_OTHER_DATA_SIZE];

	// Initialize the hardware interface.
	// Depending on which interface you have linked the
	// library to, it initializes SWI GPIO, or TWI.
	// This example does not work when SWI UART is used.
	sha204p_init();

	// Configure client.
	// Wakes up the client, reads its configuration, configures
	// it if it is not configured yet, and puts it to sleep.
	ret_code = sha204e_configure_diversify_key();
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	while (1) {
		// Wake up both devices.
		// If you put a break point here you will see the last
		// status response after every iteration.
		// 0x04 0x00 0x03 0x40 in the status response indicates that
		// the last command succeeded which is the CheckMac command.
		ret_code = sha204c_wakeup(response_status);
		if (ret_code != SHA204_SUCCESS)
			return ret_code;
		
		// Read serial number from client and pad with zeros.
		sha204p_set_device_id(SHA204_CLIENT_ADDRESS);
		memset(serial_number, 0, sizeof(serial_number));
		ret_code = sha204e_read_serial_number(command, serial_number);
	
		/*
		Obtain a random number from host device. We can generate a random number to
		be used by a pass-through nonce (TempKey.SourceFlag = Input = 1) in whatever 
		way we want but we use the host	device because it has a high-quality random 
		number generator. We are using the host and not the client device because we 
		like to show a typical accessory authentication example where the MCU this 
		code is running on and the host device are inaccessible to an adversary, 
		whereas the client device is built into an easily accessible accessory. We 
		prevent an adversary to	mount replay attacks by supplying the pass-through
		nonce. For the same reason, we do not want to use the same pass-through 
		number every time we authenticate. The same nonce would produce the same MAC 
		response. Be aware that the Random command returns a fixed number
		(0xFFFF0000FFFF0000...) when the configuration zone of the device is not locked.
		*/
		sha204p_set_device_id(SHA204_HOST_ADDRESS);

		// No need to update the seed because it gets updated with every wake / sleep
		// cycle anyway.
		ret_code = sha204m_random(command, response_random, RANDOM_NO_SEED_UPDATE);
		if (ret_code != SHA204_SUCCESS) {
			sha204e_sleep();
			return ret_code;
		}
	
		// Store padded serial number of client in TempKey of host.
		ret_code = sha204m_nonce(command, response_status, NONCE_MODE_PASSTHROUGH, serial_number);
		if (ret_code != SHA204_SUCCESS) {
			sha204e_sleep();
			return ret_code;
		}
	
		// Let host device calculate the diversified key and store it in its TempKey.
		ret_code = sha204m_gen_dig(command, response_status, GENDIG_ZONE_DATA, SHA204_KEY_PARENT, derive_key_command);
		if (ret_code != SHA204_SUCCESS) {
			sha204e_sleep();
			return ret_code;
		}
	
		// Issue a MAC command to client.
		sha204p_set_device_id(SHA204_CLIENT_ADDRESS);
		ret_code = sha204m_mac(command, response_mac, MAC_MODE_CHALLENGE, SHA204_KEY_CHILD, random_number);
		if (ret_code != SHA204_SUCCESS) {
			sha204e_sleep();
			return ret_code;
		}
	
		// Issue a CheckMac command to host. The key id does not matter in the mode used.
		sha204p_set_device_id(SHA204_HOST_ADDRESS);
		memset(checkmac_other_data, 0, sizeof(checkmac_other_data));
		memcpy(checkmac_other_data, &command[SHA204_OPCODE_IDX], CHECKMAC_CLIENT_COMMAND_SIZE);
		ret_code = sha204m_check_mac(command, response_status, CHECKMAC_MODE_BLOCK1_TEMPKEY | CHECKMAC_MODE_SOURCE_FLAG_MATCH, 
										0, random_number, &response_mac[SHA204_BUFFER_POS_DATA], checkmac_other_data);

		// Put both devices to sleep.
		sha204e_sleep();

		ret_code = sha204e_check_response_status(ret_code, response_status);
	}
		
	return ret_code;
}


/** \brief This function changes the I<SUP>2</SUP>C address of a device.

Running it will access the device with I<SUP>2</SUP>C address SHA204_CLIENT_ADDRESS
and change it to SHA204_HOST_ADDRESS as long as the configuration zone is
not locked (byte at address 87 = 0x55). Be aware that bit 3 of the I<SUP>2</SUP>C
address is also used as a TTL enable bit. So make sure you give it a value that
agrees with your system (see data sheet).
 * \return status of the operation
 */
uint8_t sha204e_change_i2c_address(void)
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;
	
	uint16_t config_address;
	
	// Make the command buffer the minimum size of the Write command.
	uint8_t command[WRITE_COUNT_SHORT];
	
	uint8_t config_data[SHA204_ZONE_ACCESS_4];

	// Make the response buffer the size of a Read response.
	uint8_t response[READ_4_RSP_SIZE];

	sha204p_init();

	sha204p_set_device_id(SHA204_CLIENT_ADDRESS);
	
	ret_code = sha204c_wakeup(response);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;
		
	// Make sure that configuration zone is not locked.
	memset(response, 0, sizeof(response));
	config_address = 84;
	ret_code = sha204m_read(command, response, SHA204_ZONE_CONFIG, config_address);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}
	if (response[4] != 0x55) {
		// Configuration zone is locked. We cannot change the I2C address.
		sha204p_sleep();
		return SHA204_FUNC_FAIL;
	}
	
	// Read device configuration at address 16 that contains the I2C address.
	memset(response, 0, sizeof(response));
	config_address = 16;
	ret_code = sha204m_read(command, response, SHA204_ZONE_CONFIG, config_address);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}
	config_data[0] = SHA204_HOST_ADDRESS;
	memcpy(&config_data[1], &response[SHA204_BUFFER_POS_DATA + 1], sizeof(config_data - 1));

	ret_code = sha204m_write(command, response, SHA204_ZONE_CONFIG, config_address, config_data, NULL);

	sha204p_sleep();
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	// Check whether we had success.
	sha204p_set_device_id(SHA204_HOST_ADDRESS);
	ret_code = sha204c_wakeup(response);
	sha204p_sleep();

	return ret_code;
}


/** \brief This function reads all 88 bytes from the configuration zone.
 *
Obtain the data by putting a breakpoint after every read and inspecting "response".

<b>Factory Defaults of Configuration Zone</b><BR>
01 23 76 ab 00 04 05 00 0c 8f b7 bd ee 55 01 00 c8 00 55 00 8f 80 80 a1 82 e0 a3 60 94 40 a0 85<BR>
86 40 87 07 0f 00 89 f2 8a 7a 0b 8b 0c 4c dd 4d c2 42 af 8f ff 00 ff 00 ff 00 1f 00 ff 00 1f 00<BR>
ff 00 ff 00 1f ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff 00 00 55 55<BR>

<b>Slot Summary</b><BR>
Slot 1 is parent key, and slot 1 is child key (DeriveKey-Roll).\n
Slot 2 is parent key, and slot 0 is child key (DeriveKey-Roll).\n
Slot 3 is parent key, and child key has to be given in Param2 (DeriveKey-Roll).\n
Slots 4, 13, and 14 are CheckOnly.\n
Slots 5 and 15 are single use.\n
Slot 8 is plain text.\n
Slot 10 is parent key and slot 10 is child key (DeriveKey-Create).\n
Slot 12 is not allowed as target.\n

<b>Slot Details</b><BR>
Byte # \t          Name    \t\t\t  Value \t\t\t  Description\n
0 - 3 \t   SN[0-3]           \t\t 012376ab   \t part of the serial number\n
4 - 7 \t   RevNum            \t\t 00040500   \t device revision (= 4)\n
8 - 12\t   SN[4-8]           \t\t 0c8fb7bdee \t part of the serial number\n
13    \t\t Reserved        \t\t\t 55       \t\t set by Atmel (55: First 16 bytes are unlocked / special case.)\n
14    \t\t I2C_Enable        \t\t 01       \t\t SWI / I2C (1: I2C)\n
15    \t\t Reserved        \t\t\t 00       \t\t set by Atmel\n
16    \t\t I2C_Address       \t\t c8       \t\t default I2C address\n
17    \t\t RFU         \t\t\t\t\t 00       \t\t reserved for future use; must be 0\n
18    \t\t OTPmode         \t\t\t 55       \t\t 55: consumption mode, not supported at this time\n
19    \t\t SelectorMode      \t\t 00       \t\t 00: Selector can always be written with UpdateExtra command.\n
20    \t\t slot  0, read   \t\t\t 8f       \t\t 8: Secret. f: Does not matter.\n
21    \t\t slot  0, write  \t\t\t 80       \t\t 8: Never write. 0: Does not matter.\n
22    \t\t slot  1, read   \t\t\t 80       \t\t 8: Secret. 0: CheckMac copy\n
23		\t\t slot  1, write  \t\t\t a1       \t\t a: MAC required (roll). 1: key id\n
24		\t\t slot  2, read   \t\t\t 82       \t\t 8: Secret. 2: Does not matter.\n
25		\t\t slot  2, write  \t\t\t e0       \t\t e: MAC required (roll) and write encrypted. 0: key id\n
26		\t\t slot  3, read   \t\t\t a3       \t\t a: Single use. 3: Does not matter.\n
27		\t\t slot  3, write  \t\t\t 60       \t\t 6: Encrypt, MAC not required (roll). 0: Does not matter.\n
28		\t\t slot  4, read   \t\t\t 94       \t\t 9: CheckOnly. 4: Does not matter.\n
29		\t\t slot  4, write  \t\t\t 40       \t\t 4: Encrypt. 0: key id\n
30		\t\t slot  5, read   \t\t\t a0       \t\t a: Single use. 0: key id\n
31		\t\t slot  5, write  \t\t\t 85       \t\t 8: Never write. 5: Does not matter.\n
32		\t\t slot  6, read   \t\t\t 86       \t\t 8: Secret. 6: Does not matter.\n
33		\t\t slot  6, write  \t\t\t 40       \t\t 4: Encrypt. 0: key id\n
34		\t\t slot  7, read   \t\t\t 87       \t\t 8: Secret. 7: Does not matter.\n
35		\t\t slot  7, write  \t\t\t 07       \t\t 0: Write. 7: Does not matter.\n
36		\t\t slot  8, read   \t\t\t 0f       \t\t 0: Read. f: Does not matter.\n
37		\t\t slot  8, write  \t\t\t 00       \t\t 0: Write. 0: Does not matter.\n
38		\t\t slot  9, read   \t\t\t 89       \t\t 8: Secret. 9: Does not matter.\n
39		\t\t slot  9, write  \t\t\t f2       \t\t f: Encrypt, MAC required (create). 2: key id\n
40		\t\t slot 10, read   \t\t\t 8a       \t\t 8: Secret. a: Does not matter.\n
41		\t\t slot 10, write  \t\t\t 7a       \t\t 7: Encrypt, MAC not required (create). a: key id\n
42		\t\t slot 11, read   \t\t\t 0b       \t\t 0: Read. b: Does not matter.\n
43		\t\t slot 11, write  \t\t\t 8b       \t\t 8: Never Write. b: Does not matter.\n
44		\t\t slot 12, read   \t\t\t 0c       \t\t 0: Read. c: Does not matter.\n
45		\t\t slot 12, write  \t\t\t 4c       \t\t 4: Encrypt, not allowed as target. c: key id\n
46		\t\t slot 13, read   \t\t\t dd       \t\t d: CheckOnly. d: key id\n
47		\t\t slot 13, write  \t\t\t 4d       \t\t 4: Encrypt, not allowed as target. d: key id\n
48		\t\t slot 14, read   \t\t\t c2       \t\t c: CheckOnly. 2: key id\n
49		\t\t slot 14, write  \t\t\t 42       \t\t 4: Encrypt. 2: key id\n
50		\t\t slot 15, read   \t\t\t af       \t\t a: Single use. f: Does not matter.\n
51		\t\t slot 15, write  \t\t\t 8f       \t\t 8: Never write. f: Does not matter.\n
52		\t\t UseFlag 0     \t\t\t\t ff       \t\t 8 uses\n
53		\t\t UpdateCount 0     \t\t 00       \t\t count = 0\n
54		\t\t UseFlag 1     \t\t\t\t ff       \t\t 8 uses\n
55		\t\t UpdateCount 1     \t\t 00       \t\t count = 0\n
56		\t\t UseFlag 2     \t\t\t\t ff       \t\t 8 uses\n
57		\t\t UpdateCount 2     \t\t 00       \t\t count = 0\n
58		\t\t UseFlag 3     \t\t\t\t 1f       \t\t 5 uses\n
59		\t\t UpdateCount 3     \t\t 00       \t\t count = 0\n
60		\t\t UseFlag 4     \t\t\t\t ff       \t\t 8 uses\n
61		\t\t UpdateCount 4     \t\t 00       \t\t count = 0\n
62		\t\t UseFlag 5     \t\t\t\t 1f       \t\t 5 uses\n
63		\t\t UpdateCount 5     \t\t 00       \t\t count = 0\n
64		\t\t UseFlag 6     \t\t\t\t ff       \t\t 8 uses\n
65		\t\t UpdateCount 6     \t\t 00       \t\t count = 0\n
66		\t\t UseFlag 7     \t\t\t\t ff       \t\t 8 uses\n
67		\t\t UpdateCount 7     \t\t 00       \t\t count = 0\n
68 - 83 \t LastKeyUse      \t\t\t 1fffffffffffffffffffffffffffffff\n
84		\t\t UserExtra\n
85		\t\t Selector    \t\t\t\t\t 00       \t\t Pause command with chip id 0 leaves this device active.\n
86		\t\t LockValue     \t\t\t\t 55       \t\t OTP and Data zones are not locked.\n
87		\t\t LockConfig    \t\t\t\t 55       \t\t Configuration zone is not locked.\n

 * \param[in]  device_id host or client device
 * \param[out] config_data pointer to all 88 bytes in configuration zone.
               Not used if NULL.
 * \return status of the operation
 */
uint8_t sha204e_read_config_zone(uint8_t device_id, uint8_t *config_data)
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;
	
	uint16_t config_address;
	
	// Make the command buffer the size of the Read command.
	uint8_t command[READ_COUNT];

	// Make the response buffer the size of the maximum Read response.
	uint8_t response[READ_32_RSP_SIZE];
	
	// Use this buffer to read the last 24 bytes in 4-byte junks.
	uint8_t response_read_4[READ_4_RSP_SIZE];
	
	uint8_t *p_response;

	sha204p_init();

	sha204p_set_device_id(device_id);

	// Read first 32 bytes. Put a breakpoint after the read and inspect "response" to obtain the data.
	ret_code = sha204c_wakeup(response);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;
		
	memset(response, 0, sizeof(response));
	config_address = 0;
	ret_code = sha204m_read(command, response, SHA204_ZONE_CONFIG | READ_ZONE_MODE_32_BYTES, config_address);
	sha204p_sleep();
	if (ret_code != SHA204_SUCCESS)
		return ret_code;
		
	if (config_data) {
		memcpy(config_data, &response[SHA204_BUFFER_POS_DATA], SHA204_ZONE_ACCESS_32);
		config_data += SHA204_ZONE_ACCESS_32;
	}		
	// Read second 32 bytes. Put a breakpoint after the read and inspect "response" to obtain the data.
	memset(response, 0, sizeof(response));
	ret_code = sha204c_wakeup(response);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	config_address += SHA204_ZONE_ACCESS_32;
	memset(response, 0, sizeof(response));
	ret_code = sha204m_read(command, response, SHA204_ZONE_CONFIG | READ_ZONE_MODE_32_BYTES, config_address);
	sha204p_sleep();
	if (ret_code != SHA204_SUCCESS)
		return ret_code;
		
	if (config_data) {
		memcpy(config_data, &response[SHA204_BUFFER_POS_DATA], SHA204_ZONE_ACCESS_32);
		config_data += SHA204_ZONE_ACCESS_32;
	}
		
	// Read last 24 bytes in six four-byte junks.
	memset(response, 0, sizeof(response));
	ret_code = sha204c_wakeup(response);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;
	
	config_address += SHA204_ZONE_ACCESS_32;
	response[SHA204_BUFFER_POS_COUNT] = 0;
	p_response = &response[SHA204_BUFFER_POS_DATA];
	memset(response, 0, sizeof(response));
	while (config_address < SHA204_CONFIG_SIZE) {
		memset(response_read_4, 0, sizeof(response_read_4));
		ret_code = sha204m_read(command, response_read_4, SHA204_ZONE_CONFIG, config_address);
		if (ret_code != SHA204_SUCCESS) {
			sha204p_sleep();
			return ret_code;
		}
		memcpy(p_response, &response_read_4[SHA204_BUFFER_POS_DATA], SHA204_ZONE_ACCESS_4);
		p_response += SHA204_ZONE_ACCESS_4;
		response[SHA204_BUFFER_POS_COUNT] += SHA204_ZONE_ACCESS_4; // Update count byte in virtual response packet.
		config_address += SHA204_ZONE_ACCESS_4;
	}	
	// Put a breakpoint here and inspect "response" to obtain the data.
	sha204p_sleep();
		
	if (ret_code == SHA204_SUCCESS && config_data)
		memcpy(config_data, &response[SHA204_BUFFER_POS_DATA], SHA204_CONFIG_SIZE - 2 * SHA204_ZONE_ACCESS_32);

	return ret_code;
}
/** @} */
