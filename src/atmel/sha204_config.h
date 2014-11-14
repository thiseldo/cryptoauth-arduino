/** \file
 *  \brief  Definitions for Configurable Values of the ATSHA204 Library
 *
 *          This file contains several library configuration sections
 *          for the three interfaces the library supports
 *          (SWI using GPIO or UART, and I2C) and one that is common
 *          to all interfaces.
 *  \author Atmel Crypto Products
 *  \date 	January 9, 2013

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

#ifndef SHA204_CONFIG_H
#   define SHA204_CONFIG_H

#include <stddef.h>                    // data type definitions

/** \defgroup atsha204_config Module 07: Configuration Definitions
 *
 * Tune the values of these timing definitions for your system.
 * Always include this file no matter whether you use SWI or I<SUP>2</SUP>C.
 * Please refer to the actual file because Doxygen cannot parse
 * nested macros with the same name.
@{ */

/** \name Configuration Definitions Common to All Interfaces
@{ */

/** \brief maximum CPU clock deviation to higher frequency (crystal etc.)
 * This value is used to establish time related worst case numbers, for
 * example to calculate execution delays and timeouts.
 */
#define CPU_CLOCK_DEVIATION_POSITIVE   (1.01)

/** \brief maximum CPU clock deviation to lower frequency (crystal etc.)
 * This value is used to establish time related worst case numbers, for
 * example to calculate execution delays and timeouts.
 */
#define CPU_CLOCK_DEVIATION_NEGATIVE   (0.99)

/** \brief number of command / response retries
 *
 * If communication is lost, re-synchronization includes waiting for the
 * longest possible execution time of a command.
 * This adds a \ref SHA204_COMMAND_EXEC_MAX delay to every retry.
 * Every increment of the number of retries increases the time
 * the library is spending in the retry loop by \ref SHA204_COMMAND_EXEC_MAX.
 */
#define SHA204_RETRY_COUNT           (1)

/** @} */


/** \name Available Definitions for Interfaces
 *
 * \brief Either un-comment one of the definitions or place it in your project settings.
 * The definitions to choose from are:
 * - SHA204_SWI_BITBANG (SWI using GPIO peripheral)
 * - SHA204_SWI_UART (SWI using UART peripheral)
 * - SHA204_I2C (I<SUP>2</SUP>C using I<SUP>2</SUP>C peripheral)
 *
@{ */
//! Dummy macro that allow Doxygen to parse this group.
#define DOXYGEN_DUMMY 0
// #define SHA204_SWI_BITBANG
// #define SHA204_SWI_UART
// #define SHA204_I2C

/** @} */

#ifndef SHA204_SWI_BITBANG
#ifndef SHA204_SWI_UART
/* If not otherwise specified, this is an i2c library */
#define SHA204_I2C
#endif
#endif


#ifdef SHA204_SWI_BITBANG
/** \name Configuration Definitions for SWI (GPIO) Interface
@{ */

/** \brief This value is the same as START_PULSE_TIME_OUT in
 *  bitbang_config.h, but in us instead of loop counts.
 */
#   define SWI_RECEIVE_TIME_OUT      ((uint16_t) 163)

//! It takes 312.5 us to send a byte (9 single-wire bits / 230400 Baud * 8 flag bits).
#   define SWI_US_PER_BYTE           ((uint16_t) 313)

/** @} */
#endif



#ifdef SHA204_SWI_UART
/** \name Configuration Definitions for SWI (UART) Interface
@{ */

//! receive timeout in us instead of loop counts
#   define SWI_RECEIVE_TIME_OUT      ((uint16_t) 153)

//! It takes 312.5 us to send a byte (9 single-wire bits / 230400 Baud * 8 flag bits).
#   define SWI_US_PER_BYTE           ((uint16_t) 313)

//! SWI response timeout is the sum of receive timeout and the time it takes to send the TX flag.
#   ifndef SHA204_RESPONSE_TIMEOUT
#      define SHA204_RESPONSE_TIMEOUT   ((uint16_t) SWI_RECEIVE_TIME_OUT + SWI_US_PER_BYTE)
#   endif

/** @} */

#endif



#if defined(SHA204_SWI_BITBANG) || defined(SHA204_SWI_UART)
/** \name Configuration Definitions for SWI Interface, Common to GPIO and UART
@{ */

//! delay before sending a transmit flag in the synchronization routine
#   define SHA204_SYNC_TIMEOUT       ((uint8_t) 85)

//! SWI response timeout is the sum of receive timeout and the time it takes to send the TX flag.
#   ifndef SHA204_RESPONSE_TIMEOUT
#      define SHA204_RESPONSE_TIMEOUT   ((uint16_t) SWI_RECEIVE_TIME_OUT + SWI_US_PER_BYTE)
#   endif

/** @} */

#endif



#ifdef SHA204_I2C
/** \name Configuration Definitions for I2C Interface
@{ */

/** \brief For I<SUP>2</SUP>C, the response polling time is the time
 *         it takes to send the I<SUP>2</SUP>C address.
 *
 *         This value is used to timeout when waiting for a response.
 */
#   ifndef SHA204_RESPONSE_TIMEOUT
#      define SHA204_RESPONSE_TIMEOUT     ((uint16_t) 37)
#   endif

/** @} */

#endif


/** @} */

#endif
