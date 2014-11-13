/** \file
 *  \brief Definitions for Hardware Dependent Part of ATSHA204 Physical Layer
 *         Using I<SUP>2</SUP>C for Communication
 *  \author Atmel Crypto Products
 *  \date January 14, 2013
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

#ifndef I2C_PHYS_H_
#   define I2C_PHYS_H_

#include <stdint.h>                       // data type definitions

/** \defgroup atsha204_i2c_hardware Module 18: I2C Interface
 * Definitions are supplied for various I<SUP>2</SUP>C configuration values
 * such as clock, timeouts, and error codes.
*/

//! I2C clock
#define I2C_CLOCK                         (400000.0)

//! Use pull-up resistors.
#define I2C_PULLUP

/** \brief number of polling iterations for TWINT bit in TWSR after
 *         creating a Start condition in #i2c_send_start()
 *
 * Adjust this value considering how long it takes to check a status bit
 * in the TWI status register, decrement the timeout counter,
 * compare its value with 0, and branch.
 */
#define I2C_START_TIMEOUT                ((uint8_t) 250)

/** \brief number of polling iterations for TWINT bit in TWSR after sending
 *         or receiving a byte.
 *
 * Adjust this value considering how long it takes to check a status bit
 * in the TWI status register, decrement the timeout counter,
 * compare its value with 0, branch, and to send or receive one byte.
 */
#define I2C_BYTE_TIMEOUT                 ((uint8_t) 200)

/** \brief number of polling iterations for TWSTO bit in TWSR after
 *         creating a Stop condition in #i2c_send_stop().
 *
 * Adjust this value considering how long it takes to check a status bit
 * in the TWI control register, decrement the timeout counter,
 * compare its value with 0, and branch.
 */
#define I2C_STOP_TIMEOUT                 ((uint8_t) 250)


// error codes for physical hardware dependent module
// Codes in the range 0x00 to 0xF7 are shared between physical interfaces (SWI, TWI, SPI).
// Codes in the range 0xF8 to 0xFF are special for the particular interface.
#define I2C_FUNCTION_RETCODE_SUCCESS     ((uint8_t) 0x00) //!< Communication with device succeeded.
#define I2C_FUNCTION_RETCODE_COMM_FAIL   ((uint8_t) 0xF0) //!< Communication with device failed.
#define I2C_FUNCTION_RETCODE_TIMEOUT     ((uint8_t) 0xF1) //!< Communication timed out.
#define I2C_FUNCTION_RETCODE_NACK        ((uint8_t) 0xF8) //!< TWI nack


void    i2c_enable(void);
void    i2c_disable(void);
uint8_t i2c_send_start(void);
uint8_t i2c_send_stop(void);
uint8_t i2c_send_bytes(uint8_t count, uint8_t *data);
uint8_t i2c_receive_byte(uint8_t *data);
uint8_t i2c_receive_bytes(uint8_t count, uint8_t *data);


/** @} */

#endif
