/** \file
 *  \brief  Application Examples that Use the ECC108 Library
 *  \author Atmel Crypto Products
 *  \date   January 29, 2014
 *

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

* \atmel_crypto_device_library_license_stop
*/

#include <stddef.h>            // data type definitions
#include "ecc108_examples.h"   // definitions and declarations for example functions
#include "ecc108_physical.h"   // function definitions for the physical layer

// ---------------------------- Un-comment one example --------------------------
#define ECC108_EXAMPLE_SEND_INFO_COMMAND
//#define ECC108_EXAMPLE_CHECKMAC_DEVICE
//#define ECC108_EXAMPLE_CHECKMAC_FIRMWARE
//#define ECC108_EXAMPLE_VERIFY_EXTERNAL
//#define ECC108_EXAMPLE_VERIFY_EXTERNAL_283
//#define ECC108_EXAMPLE_VERIFY_HOST
//#define ECC108_EXAMPLE_VERIFY_HOST_283
//#define ECC108_EXAMPLE_CHANGE_I2C_ADDRESS


/** \brief This application calls one example function that can be selected with a compilation switch.
 * \return exit status of application
 */
int main(void)
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;

	ecc108p_init();

#ifdef ECC108_EXAMPLE_SEND_INFO_COMMAND
	ret_code = ecc108e_send_info_command();

#elif defined(ECC108_EXAMPLE_CHECKMAC_DEVICE)
	ret_code = ecc108e_checkmac_device();

#elif defined(ECC108_EXAMPLE_CHECKMAC_FIRMWARE)
	ret_code = ecc108e_checkmac_firmware();

#elif defined(ECC108_EXAMPLE_VERIFY_EXTERNAL)
	ret_code = ecc108e_verify_external();

#elif defined(ECC108_EXAMPLE_VERIFY_EXTERNAL_283)
	ret_code = ecc108e_verify_external_283();

#elif defined(ECC108_EXAMPLE_VERIFY_HOST)
	ret_code = ecc108e_verify_host();

#elif defined(ECC108_EXAMPLE_VERIFY_HOST_283)
	ret_code = ecc108e_verify_host_283();

#elif defined(ECC108_EXAMPLE_CHANGE_I2C_ADDRESS) && defined(ECC108_I2C)
	// Changes ECC108_CLIENT_ADDRESS to ECC108_HOST_ADDRESS that are defined in ecc108_examples.h.
	ret_code = ecc108e_change_i2c_address(ECC108_HOST_ADDRESS);

#else
#   error Please define one example.
#endif

	return (int) ret_code;
}
