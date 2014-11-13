/** \file
 *  \brief  Definitions and Prototypes for Physical Layer Interface of ATSHA204 Library
 *  \author Atmel Crypto Products
 *  \date 	January 11, 2013
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
#ifndef SHA204_PHYSICAL_H
#   define SHA204_PHYSICAL_H

#include <stdint.h>                                  // data type definitions

#include "sha204_config.h"                           // configuration values


/** \defgroup sha204_physical Module 03: Header File for Interface Abstraction Modules
 *
 * \brief This header file contains definitions and function prototypes for SWI and I<SUP>2</SUP>C.
 * The prototypes are the same for both interfaces but are of course implemented differently.
 * Always include this file no matter whether you use SWI or I<SUP>2</SUP>C.
@{ */

#define SHA204_RSP_SIZE_MIN          ((uint8_t)  4)  //!< minimum number of bytes in response
#define SHA204_RSP_SIZE_MAX          ((uint8_t) 35)  //!< maximum size of response packet

#define SHA204_BUFFER_POS_COUNT      (0)             //!< buffer index of count byte in command or response
#define SHA204_BUFFER_POS_DATA       (1)             //!< buffer index of data in response

//! width of Wakeup pulse in 10 us units
#define SHA204_WAKEUP_PULSE_WIDTH    (uint8_t) (6.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5)

//! delay between Wakeup pulse and communication in ms
#define SHA204_WAKEUP_DELAY          (uint8_t) (3.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5)


uint8_t sha204p_send_command(uint8_t count, uint8_t *command);
uint8_t sha204p_receive_response(uint8_t size, uint8_t *response);
void    sha204p_init(void);
void    sha204p_set_device_id(uint8_t id);
uint8_t sha204p_wakeup(void);
uint8_t sha204p_idle(void);
uint8_t sha204p_sleep(void);
uint8_t sha204p_reset_io(void);
uint8_t sha204p_resync(uint8_t size, uint8_t *response);

/** @} */

#endif
