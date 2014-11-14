/** \file
 *  \brief Definitions for Hardware Dependent Part of ATSHA204 Physical Layer
 *         Using GPIO for Communication
 *  \author Atmel Crypto Products
 *  \date January 14, 2013
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
#ifndef BITBANG_CONFIG_H
#   define BITBANG_CONFIG_H

#include <avr/io.h>                // GPIO definitions
#include <avr/interrupt.h>         // interrupt definitions


/** \defgroup atsha204_swi_gpio_config Module 17: SWI Configuration - GPIO
 *
 * Two definition blocks are supplied:
 * - port definitions for various Atmel evaluation kits
 * - loop definitions that result in correct pulse widths for an AVR CPU
 *   running at 16 MHz
*/

#define swi_enable_interrupts  sei //!< enable interrupts
#define swi_disable_interrupts cli //!< disable interrupts

//#define AT88CK_DEBUG
//
// first socket
#ifdef AT88CK109STK3           // Javan daughter board
#   define SIG2_BIT      (7)        //!< bit position of port register for second device
#   define CLIENT_ID     (0)        //!< identifier for client
#   define PORT_DDR      (DDRB)     //!< direction register for device id 0
#   define PORT_OUT      (PORTB)    //!< output port register for device id 0
#   define PORT_IN       (PINB)     //!< input port register for device id 0
#elif defined(AT88CK101STK3)             // Javan Jr. daughter board, 3-pin device
#   define SIG2_BIT      (7)        //!< bit position of port register for second device
#   define CLIENT_ID     (0)        //!< identifier for client
#   define PORT_DDR      (DDRB)     //!< direction register for device id 0
#   define PORT_OUT      (PORTB)    //!< output port register for device id 0
#   define PORT_IN       (PINB)     //!< input port register for device id 0
#elif defined(AT88CK101STK8)             // Javan Jr. daughter board, 8-pin device
#   define SIG2_BIT      (2)        //!< bit position of port register for second device
#   define CLIENT_ID     (0)        //!< identifier for client
#   define PORT_DDR      (DDRB)     //!< direction register for device id 0
#   define PORT_OUT      (PORTB)    //!< output port register for device id 0
#   define PORT_IN       (PINB)     //!< input port register for device id 0
#elif defined(AT88CK454) || defined(RHINO_RED)   // Rhino Black or Red
#   define SIG2_BIT      (2)        //!< bit position of port register for second device
#   define CLIENT_ID     (0)        //!< identifier for client
#   define PORT_DDR      (DDRD)     //!< direction register for device id 0
#   define PORT_OUT      (PORTD)    //!< output port register for device id 0
#   define PORT_IN       (PIND)     //!< input port register for device id 0
#elif defined(AT88CK101STK3_TWO)                // two Javan Jr. daughter boards
#   define SIG2_BIT      (6)        //!< bit position of port register for second device
#   define CLIENT_ID     (0)        //!< identifier for client
#   define PORT_DDR      (DDRB)     //!< direction register for device id 0
#   define PORT_OUT      (PORTB)    //!< output port register for device id 0
#   define PORT_IN       (PINB)     //!< input port register for device id 0
#elif defined(AT88CK_DEBUG)
#   define SIG2_BIT      (1)        //!< bit position of port register for second device
#   define CLIENT_ID     (0)        //!< identifier for client
#   define PORT_DDR      (DDRD)     //!< direction register for device id 0
#   define PORT_OUT      (PORTD)    //!< output port register for device id 0
#   define PORT_IN       (PIND)     //!< input port register for device id 0
#else
#   define SIG2_BIT      (2)        //!< bit position of port register for second device
#   define CLIENT_ID     (0)        //!< identifier for client
#   define PORT_DDR      (DDRD)     //!< direction register for device id 0
#   define PORT_OUT      (PORTD)    //!< output port register for device id 0
#   define PORT_IN       (PIND)     //!< input port register for device id 0
#endif

// second socket
#ifdef AT88CK101STK3_TWO
#   define SIG1_BIT      (7)        //!< bit position of port register for first device
#else
#   define SIG1_BIT      (6)        //!< bit position of port register for first device
#endif
#define HOST_ID          (1)        //!< identifier for host

/** \brief Debug pin that indicates pulse edge detection. This is only enabled if compilation switch DEBUG_BITBANG is used.
           To debug timing, disable host power (H1 and H2 on AT88CK109BK8 daughter board) and connect logic analyzer
           or storage oscilloscope to the H2 pin that is closer to the H1 header.
           The logic analyzer from Saleae (www.saleae.com) comes with a protocol analyzer for this Atmel SWI protocol. 
*/
//#define DEBUG_BITBANG
#ifdef DEBUG_BITBANG
#   ifdef AT88CK101STK3_TWO
#      define DEBUG_PORT_DDR  (DDRD)                           //!< direction register for debug pin
#      define DEBUG_PORT_OUT  (PORTD)                          //!< output port register for debug pin
#      define DEBUG_BIT       (0)                              //!< what pin to use for debugging
#   else
#      define DEBUG_PORT_DDR  (DDRB)                           //!< direction register for debug pin
#      define DEBUG_PORT_OUT  (PORTB)                          //!< output port register for debug pin
#      define DEBUG_BIT       (6)                              //!< what pin to use for debugging
#   endif
#   define DEBUG_LOW       DEBUG_PORT_OUT &= ~_BV(DEBUG_BIT)   //!< set debug pin low
#   define DEBUG_HIGH      DEBUG_PORT_OUT |= _BV(DEBUG_BIT)    //!< set debug pin high
#else
#   define DEBUG_LOW
#   define DEBUG_HIGH
#endif

/** \name Macros for Bit-Banged SWI Timing

Times to drive bits at 230.4 kbps.
For a CPU clock of 16 MHz on an 8-bit AVR, the delay loops used
take about 580 ns per iteration. Another 800 ns are needed to
access the port.
@{ */

//! delay macro for width of one pulse (start pulse or zero pulse, in ns)
// should be 4.34 us, is 4.33 us
#define BIT_DELAY_1        {volatile uint8_t delay = 6; while (delay--);}

//! time to keep pin high for five pulses plus stop bit (used to bit-bang CryptoAuth 'zero' bit, in ns)
// should be 26.04 us, is 26.38 us
#define BIT_DELAY_5        {volatile uint8_t delay = 44; while (delay--);}

//! time to keep pin high for seven bits plus stop bit (used to bit-bang CryptoAuth 'one' bit)
// should be 34.72 us, is 35.00 us
#define BIT_DELAY_7        {volatile uint8_t delay = 59; while (delay--);}

//! turn around time when switching from receive to transmit
// should be 15 us, is 15 us
#define RX_TX_DELAY        {volatile uint8_t delay = 25; while (delay--);}

// One loop iteration for edge detection takes about 0.6 us on this hardware.
// Lets set the timeout value for start pulse detection to the uint8_t maximum.
//! This value is decremented while waiting for the falling edge of a start pulse.
#define START_PULSE_TIME_OUT  (255)

// We measured a loop count of 8 for the start pulse. That means it takes about
// 0.6 us per loop iteration. Maximum time between rising edge of start pulse
// and falling edge of zero pulse is 8.6 us. Therefore, a value of 26 (around 15 us)
// gives ample time to detect a zero pulse and also leaves enough time to detect
// the following start pulse.
// The values above were established using the WinAVR 2010 compiler.
// The code runs faster when compiled with the compiler version of Atmel Studio 6.
// In this case a timeout value of 26 leads to a timeout of 10 us which is still
// greater than 8.6 us.
//! This value is decremented while waiting for the falling edge of a zero pulse.
#define ZERO_PULSE_TIME_OUT    (26)

/** @} */

#endif
