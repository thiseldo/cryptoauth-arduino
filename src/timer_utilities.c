/** \file
 *  \brief Timer Utility Functions
 *  \author Atmel Crypto Products
 *  \date January 11, 2013
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

#include <stdint.h>                           // data type definitions

/** \defgroup timer_utilities Module 09: Timers
 *
 * This module implements timers used during communication.
 * They are implemented using loop counters. But if you have hardware
 * timers available, you can implement the functions using them.
@{ */

// The values below are valid for an AVR 8-bit processor running at 16 MHz.
// Code is compiled with optimization set to -O1.

#if F_CPU == 16000000UL
//! Fill the inner loop of delay_10us() with these CPU instructions to achieve 10 us per iteration.
#   define   TIME_UTILS_US_CALIBRATION           //__asm__ volatile ("\n\tnop\n\tnop\n\tnop\n")

/** Decrement the inner loop of delay_10us() this many times to achieve 10 us per
 *  iteration of the outer loop.
 */
#   define   TIME_UTILS_LOOP_COUNT            ((uint8_t)  14)

//! The delay_ms function calls delay_10us with this parameter.
#   define   TIME_UTILS_MS_CALIBRATION        ((uint8_t) 104)

#elif F_CPU == 8000000UL
//! Fill the inner loop of delay_10us() with these CPU instructions to achieve 10 us per iteration.
#   define   TIME_UTILS_US_CALIBRATION           __asm__ volatile ("\n\tnop\n\tnop\n\tnop\n\tnop\n")

/** \brief Decrement the inner loop of delay_10us() this many times to achieve 10 us per
 *         iteration of the outer loop.
 */
#   define   TIME_UTILS_LOOP_COUNT            ((uint8_t)  0)

//! The delay_ms function calls delay_10us with this parameter.
#   define   TIME_UTILS_MS_CALIBRATION        ((uint8_t) 100)

#elif F_CPU == 2000000UL
//! Fill the inner loop of delay_10us() with these CPU instructions to achieve 10 us per iteration.
#   define   TIME_UTILS_US_CALIBRATION           __asm__ volatile ("\n\tnop\n")

/** \brief Decrement the inner loop of delay_10us() this many times to achieve 10 us per
 *         iteration of the outer loop.
 */
#   define   TIME_UTILS_LOOP_COUNT            ((uint8_t)  1)

//! The delay_ms function calls delay_10us with this parameter.
#   define   TIME_UTILS_MS_CALIBRATION        ((uint8_t) 91)

#elif CONFIG_SYSCLK_SOURCE == SYSCLK_SRC_RC32MHZ
// Xmega
//! Fill the inner loop of delay_10us() with these CPU instructions to achieve 10 us per iteration.
#   define   TIME_UTILS_US_CALIBRATION           //__asm__ volatile ("\n\tnop\n\tnop\n\tnop\n")

/** \brief Decrement the inner loop of delay_10us() this many times to achieve 10 us per
 *         iteration of the outer loop.
 */
#   define   TIME_UTILS_LOOP_COUNT            ((uint8_t)  28)

//! The delay_ms function calls delay_10us with this parameter.
#   define   TIME_UTILS_MS_CALIBRATION        ((uint8_t) 104)

#else
#   error   Time macros are not defined.
#endif


/** \brief This function delays for a number of tens of microseconds.
 *
 * This function will not time correctly, if one loop iteration
 * plus the time it takes to enter this function takes more than 10 us.
 * \param[in] delay number of 0.01 milliseconds to delay
 */
void delay_10us(uint8_t delay)
{
	volatile uint8_t delay_10us;

	for (; delay > 0; delay--) {
		for (delay_10us = TIME_UTILS_LOOP_COUNT; delay_10us > 0; delay_10us--);
		TIME_UTILS_US_CALIBRATION;
	}
}


/** \brief This function delays for a number of milliseconds.
 *
 *         You can override this function if you like to do
 *         something else in your system while delaying.
 * \param[in] delay number of milliseconds to delay
 */
void delay_ms(uint8_t delay)
{
	uint8_t i;
	for (i = delay; i > 0; i--)
		delay_10us(TIME_UTILS_MS_CALIBRATION);
}

/** @} */
