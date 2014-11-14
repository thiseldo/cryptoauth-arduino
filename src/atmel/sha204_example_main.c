/** \file
    \brief  Main Function for Application Examples that Use the ATSHA204 Library
    \author Atmel Crypto Products
    \date   January 15, 2013

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

#include <stddef.h>                   // data type definitions
#include "sha204_examples.h"          // definitions and declarations for example functions
#include "sha204_comm_marshaling.h"   // definitions and declarations for the Command Marshaling module


/** \defgroup atsha204_main Module 11: Main Application
 *
Example functions are given that demonstrate the device.
They can be selected via compilation switches (SHA204_EXAMPLE_...) found in
\ref sha204_examples.h.\n
Please refer to \ref sha204_examples.c for a detailed description of 
those examples. Most examples implement an authentication scheme.
Compiling them will give you a quick and rough overlook of RAM and flash resources.
An authentication with low security (E.g. replay attacks are possible.) requires
the least resources, followed by command sequences with higher security.
An implementation where the expected MAC is calculated in firmware 
(soft SHA-256) needs the biggest resources.\n
The best example to start with is the SHA204_EXAMPLE_READ_CONFIG_ZONE example.
Building and running it verifies that your hardware is set up correctly and
communication is working. This example does not depend on any personalization of
the device and does not make any modifications to the device. It only reads from
the configuration zone which is always readable, independent of the lock status of
the device.
@{ */

/** \brief This application calls one example function that can be selected with a compilation switch
           defined in \ref sha204_examples.h.

The example functions for SHA204_EXAMPLE_CHECKMAC_DEVICE, SHA204_EXAMPLE_CHECKMAC_FIRMWARE,
and SHA204_EXAMPLE_DIVERSIFY_KEY do not return since they are running in an endless loop.
 * \return exit status of application
 */
int main(void)
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;

#ifdef SHA204_EXAMPLE_READ_CONFIG_ZONE
	// You can supply an array of 88 bytes if you like to call this function from your application.
	uint8_t config_data[SHA204_CONFIG_SIZE];
	ret_code = sha204e_read_config_zone(SHA204_CLIENT_ADDRESS, config_data);
//	ret_code = sha204e_read_config_zone(SHA204_CLIENT_ADDRESS, NULL);

#elif defined(SHA204_EXAMPLE_CHECKMAC_DEVICE)
	ret_code = sha204e_checkmac_device();

#elif defined(SHA204_EXAMPLE_CHECKMAC_FIRMWARE)
	ret_code = sha204e_checkmac_firmware();

// These examples run only with two devices and only when using I2C or SWI bitbang. 
#elif (SHA204_CLIENT_ADDRESS != SHA204_HOST_ADDRESS) && !defined(SHA204_SWI_UART)
#   ifdef SHA204_EXAMPLE_DERIVE_KEY
// The example configures one device to serve as a client. The other device can be used as a 
// host in its default configuration.
	ret_code = sha204e_checkmac_derived_key();
	
#   elif defined(SHA204_EXAMPLE_DIVERSIFY_KEY)
// The example configures one device to serve as a client. The other device can be used as a 
// host in its default configuration.
	ret_code = sha204e_checkmac_diversified_key();
	
#   else
#      error You have to define one example.
#   endif

#elif defined(SHA204_EXAMPLE_CHANGE_I2C_ADDRESS) && defined(SHA204_I2C)
	// Changes SHA204_CLIENT_ADDRESS to SHA204_HOST_ADDRESS that are defined in sha204_examples.h.
	ret_code = sha204e_change_i2c_address();

#else
#   error You have to define one example in sha204_examples.h.

#endif

	return (int) ret_code;
}
/** @} */
