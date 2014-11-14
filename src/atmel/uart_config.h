/** \file
 *  \brief Definitions for Hardware Dependent Part of the  Physical Layer
 *         of the ATSHA204 Library Using a UART
 *  \author Atmel Crypto Products
 *  \date January 15, 2013
 *
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
#ifndef UART_CONFIG_H
#   define UART_CONFIG_H

#include <avr/io.h>              // GPIO definitions


/** \defgroup atsha204_swi_uart_config Module 14: SWI Configuration - UART
 *
 * This module contains hardware configuration values for the UART
 * implementation of the single-wire interface. It uses macro definitions
 * from avr/io.h for an AT90USB1287 micro-controller.
*/


//! baud rate for SHA204 device in single-wire mode
#define BAUD_RATE                (230400UL)

//! time in us it takes for decrementing a uint8_t and branching
#define TIME_PER_LOOP_ITERATION  (0.8)

/** \brief number of polling iterations over UART register before timing out
 *
 * The polling iteration takes about 0.8 us.
 * For tx, we would need to wait bit time = 39 us.
 * For rx, we need at least wait for
 * tx / rx turn-around time + bit time = 95 us + 39 us = 134 us.
 * Let's make the timeout larger to be safe.
 */
#define BIT_TIMEOUT		         ((uint8_t) (250.0 / TIME_PER_LOOP_ITERATION))

//! Delay for this many loop iterations before sending.
#define RX_TX_DELAY              ((uint8_t)  (15.0 / TIME_PER_LOOP_ITERATION))

//! direction register when using UART pin for Wake-up
#define UART_GPIO_DDR            DDRD

//! output register when using UART pin for Wake-up
#define UART_GPIO_OUT            PORTD

//! bit position when using UART rx pin for Wake-up
#define UART_GPIO_PIN_RX         _BV(PD2)

//! bit position when using UART tx pin for Wake-up
#define UART_GPIO_PIN_TX         _BV(PD3)

#ifdef DEBUG_UART
#   define DEBUG_PORT_DDR        (DDRB)                              //!< direction register for debug pin
#   define DEBUG_PORT_OUT        (PORTB)                             //!< output port register for debug pin
#   define DEBUG_BIT             (PB6)                               //!< pin used for debugging
#   define DEBUG_LOW             DEBUG_PORT_OUT &= ~_BV(DEBUG_BIT)   //!< set debug pin low
#   define DEBUG_HIGH            DEBUG_PORT_OUT |= _BV(DEBUG_BIT)    //!< set debug pin high
#else
#   define DEBUG_LOW                                                 //!< undefine debugging macro
#   define DEBUG_HIGH                                                //!< undefine debugging macro

#endif


/** @} */

#endif
