#ifdef __cplusplus
extern "C" {
#endif
/** \file
 *  \brief  Definitions and Prototypes for Communication Layer of ECC108 Library
 *  \author Atmel Crypto Products
 *  \date   October 21, 2013

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

#ifndef ECC108_COMM_H
#   define ECC108_COMM_H

#include <stddef.h>                  // data type definitions

#include "ecc108_physical.h"         // declarations that are common to all interface implementations

/** \defgroup atecc108_communication Module 02: Communication
 *
 * This module implements communication with the device. It does not depend on the interface
 * (SWI or I2C).
 *
 * Basic communication flow:
 * - Calculate CRC of command packet and append.
 * - Send command and repeat if it failed.
 * - Delay for minimum command execution time.
 * - Poll for response until maximum execution time. Repeat if communication failed.
 *
 * Retries are implemented including sending the command again depending on the type
 * of failure. A retry might include waking up the device which will be indicated by
 * an appropriate return status. The number of retries is defined with a macro and
 * can be set to 0 at compile time.
@{ */

//! maximum command delay
#define ECC108_COMMAND_EXEC_MAX      ((uint8_t) (120.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! minimum number of bytes in command (from count byte to second CRC byte)
#define ECC108_CMD_SIZE_MIN          ((uint8_t)  7)

//! maximum size of command packet (Verify)
#define ECC108_CMD_SIZE_MAX          ((uint8_t) 4 * 36 + 7)

//! number of CRC bytes
#define ECC108_CRC_SIZE              ((uint8_t)  2)

//! buffer index of status byte in status response
#define ECC108_BUFFER_POS_STATUS     (1)

//! buffer index of first data byte in data response
#define ECC108_BUFFER_POS_DATA       (1)

//! status byte after wake-up
#define ECC108_STATUS_BYTE_WAKEUP    ((uint8_t) 0x11)

//! command parse error
#define ECC108_STATUS_BYTE_PARSE     ((uint8_t) 0x03)

//! command ECC error
#define ECC108_STATUS_BYTE_ECC       ((uint8_t) 0x05)

//! command execution error
#define ECC108_STATUS_BYTE_EXEC      ((uint8_t) 0x0F)

//! communication error
#define ECC108_STATUS_BYTE_COMM      ((uint8_t) 0xFF)


void ecc108c_calculate_crc(uint8_t length, uint8_t *data, uint8_t *crc);
uint8_t ecc108c_check_crc(uint8_t *response);
uint8_t ecc108c_wakeup(uint8_t *response);
uint8_t ecc108c_send_and_receive(uint8_t *tx_buffer, uint8_t rx_size, uint8_t *rx_buffer,
				uint8_t execution_delay, uint8_t execution_timeout);
uint8_t ecc108c_resync(uint8_t size, uint8_t *response);
/** @} */

#endif
#ifdef __cplusplus
}
#endif
