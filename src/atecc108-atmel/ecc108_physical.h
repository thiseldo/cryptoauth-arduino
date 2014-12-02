#ifdef __cplusplus
extern "C" {
#endif
/** \file
 *  \brief  Definitions and Prototypes for Physical Layer Interface of ECC108 Library
 *  \author Atmel Crypto Products
 *  \date 	July 10, 2013

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
#ifndef ECC108_PHYSICAL_H
#   define ECC108_PHYSICAL_H

#include <stdint.h>                                  // data type definitions

#include "ecc108_config.h"                           // configuration values


/** \defgroup atecc108_physical Module 03: Header File for Interface Abstraction Modules
 *
 * \brief This header file contains definitions and function prototypes for SWI and I2C.
 * The prototypes are the same for both interfaces but are of course implemented differently.
 * Always include this file no matter whether you use SWI or I2C.
@{ */

#define ECC108_RSP_SIZE_MIN          ((uint8_t)  4)  //!< minimum number of bytes in response
#define ECC108_RSP_SIZE_72           ((uint8_t) 75)  //!< size of response packet containing 64 bytes data
#define ECC108_RSP_SIZE_64           ((uint8_t) 67)  //!< size of response packet containing 64 bytes data
#define ECC108_RSP_SIZE_32           ((uint8_t) 35)  //!< size of response packet containing 32 bytes data
#define ECC108_RSP_SIZE_MAX          ((uint8_t) 75)  //!< maximum size of response packet (GenKey and Verify command)

#define ECC108_BUFFER_POS_COUNT      (0)             //!< buffer index of count byte in command or response
#define ECC108_BUFFER_POS_DATA       (1)             //!< buffer index of data in response

/** width of Wakeup pulse in 10 us units
	Device versions <= 0x1001 need a longer pulse of 120 us instead of 60 us.
*/
#define ECC108_WAKEUP_PULSE_WIDTH    (uint8_t) (12.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5)

/** delay between Wakeup pulse and communication in 10 us units
	Device versions <= 0x1001 need a longer delay of 2 ms instead of 0.5 ms.
*/
#define ECC108_WAKEUP_DELAY          (uint8_t) (200.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5)


uint8_t ecc108p_send_command(uint8_t count, uint8_t *command);
uint8_t ecc108p_receive_response(uint8_t size, uint8_t *response);
void    ecc108p_init(void);
void    ecc108p_set_device_id(uint8_t id);
uint8_t ecc108p_wakeup(void);
uint8_t ecc108p_idle(void);
uint8_t ecc108p_sleep(void);
uint8_t ecc108p_reset_io(void);
uint8_t ecc108p_resync(uint8_t size, uint8_t *response);

/** @} */

#endif
#ifdef __cplusplus
}
#endif
