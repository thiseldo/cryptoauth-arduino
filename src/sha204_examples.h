/** \file
 *  \brief  Application Examples That Use the ATSHA204 Library
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
 *
 *   Example functions are given that demonstrate the device.
 *   The examples demonstrate client / host scenarios with a random challenge.
 *   Using a random challenge makes replay attacks impossible.
 *   Examples that need two devices (advanced examples) run only with
 *   I<SUP>2</SUP>C devices or SWI devices using GPIO. When running the advanced examples
 *   with SWI devices, their SDA cannot be shared. Therefore, these examples run 
 *   only in the bit-banged and not in the UART implementation of SWI.
 *   It is possible for SWI devices to share SDA, but then the Pause command
 *   has to be used to idle all devices except one to communicate with.
 *   In such a system, the Selector byte of every device has to be unique
 *   and not 0 which is the default when shipped.
*/
#ifndef SHA204_EXAMPLES_H
#   define SHA204_EXAMPLES_H

#include <stdint.h>                   // data type definitions


/** \ingroup  sha204_examples Example Definitions
@{ */

/** \brief This definition selects a simple MAC / CheckMac example using
 * an ATSHA204 as the host (key storage and SHA-256 calculation).
*/
#define SHA204_EXAMPLE_CHECKMAC_DEVICE    1

/** \brief This definition selects a simple MAC / CheckMac example using
 * firmware as the host (key storage and SHA-256 calculation).
 */
#define SHA204_EXAMPLE_CHECKMAC_FIRMWARE  2

/** \brief This definition selects an advanced MAC / CheckMac example using
 *  a derived key. This example runs only with two devices.
 */
#define SHA204_EXAMPLE_DERIVE_KEY         3

/** \brief This definition selects an advanced MAC / CheckMac example using
 *  a diversified key. This example runs only with two devices.
 */
#define SHA204_EXAMPLE_DIVERSIFY_KEY      4

/** \brief This definition selects a utility that changes the I2C default
 *  address of the device to SHA204_HOST_ADDRESS.
 *
 *  You need to change the address on one device from its default
 *  in order to run the advanced MAC / CheckMac examples.
 */
#define SHA204_EXAMPLE_CHANGE_I2C_ADDRESS 5

/** \brief This definition selects a utility that reads all 88 bytes from
 *  the configuration zone.
 *
 *  This gives you easy access to the device configuration
 *  (e.g. serial number, lock status, configuration of keys).
 */
#define SHA204_EXAMPLE_READ_CONFIG_ZONE   6

/** -------------------- Define an example. --------------------------
 *
 */
#define SHA204_EXAMPLE   SHA204_EXAMPLE_CHECKMAC_DEVICE

/** \brief Use this definition if you like to lock the configuration zone
of the host during personalization.

Once the configuration zone is locked you cannot modify
the configuration zone anymore, but the ATSHA204 device will then generate
true random numbers instead of a 0xFFFF0000FFFF0000... sequence.
The example assumes that the data line of the host is
much less accessible by an adversary than the data line of the client.
Therefore, the example requests a random number from the host and not
the client, since an adversary could take over the data line and
inject a number of her choice.
*/
#define SHA204_EXAMPLE_CONFIG_WITH_LOCK   0

/** @} */


#ifdef SHA204_I2C
/** \brief I2C address for client device
If you have two devices at your disposal you can run an example as a real-world
host / client scenario. You have to change the address of one of the devices
by writing it to configuration zone address 16.
Be aware that bit 3 of the I2C address is also used to configure the input level
reference (see data sheet table 2-1).
To change the address you can run the \ref SHA204_EXAMPLE_READ_CONFIG_ZONE example.
*/
#   define SHA204_CLIENT_ADDRESS        (0xC8)
/** \brief I2C address for host device
To make the simple Mac / CheckMac I2C examples work out-of-the-box without 
changing the I2C address for the host device, you can make the host address the
same as the client address. See \ref SHA204_CLIENT_ADDRESS.
*/
//#   define SHA204_HOST_ADDRESS          SHA204_CLIENT_ADDRESS
#   define SHA204_HOST_ADDRESS          (0xCA)
#else
/** \ingroup  sha204_examples Device Selectors
These settings have an effect only when using bit-banging where the SDA of every 
device is connected to its own GPIO pin. When using only one UART the SDA of both 
devices is connected to the same GPIO pin. In that case you have create a
version of \ref sha204p_set_device_id that would use a Pause command. (Refer
to data sheet about the Pause command.)
@{ */
#   define SHA204_CLIENT_ADDRESS        (0x00)
#   define SHA204_HOST_ADDRESS          (0x01)
/** @} */
#endif

// Check example selection against project selection.
#if (SHA204_EXAMPLE == SHA204_EXAMPLE_DERIVE_KEY || SHA204_EXAMPLE == SHA204_EXAMPLE_DIVERSIFY_KEY)
#   ifdef SHA204_SWI_UART
#      error The selected example will not run under the UART project.
#   elif SHA204_CLIENT_ADDRESS == SHA204_HOST_ADDRESS
#      error The selected example needs different addresses for client and host.
#   endif
#endif
#if (SHA204_EXAMPLE == SHA204_EXAMPLE_CHANGE_I2C_ADDRESS && !defined(SHA204_I2C))
#   error The selected example will only run under the I2C project.
#endif


/** \ingroup  sha204_examples Key Identifiers Used by the Examples
Do not change these key identifiers since related values (configuration addresses)
are hard-coded in associated functions.
@{ */
#define SHA204_KEY_ID           ( 0)
#define SHA204_KEY_PARENT       (13)
#define SHA204_KEY_CHILD        (10)
/** @} */

#define sha204e_wakeup_sleep()   {sha204p_wakeup(); sha204p_sleep();}

uint8_t sha204e_checkmac_device(void);
uint8_t sha204e_checkmac_firmware(void);
uint8_t sha204e_checkmac_derived_key(void);
uint8_t sha204e_checkmac_diversified_key(void);
uint8_t sha204e_change_i2c_address(void);
uint8_t sha204e_read_config_zone(uint8_t device_id, uint8_t *config_data);

#endif
