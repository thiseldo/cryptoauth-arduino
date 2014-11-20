/** \file
 *  \brief Functions of Hardware Dependent Part of ATSHA204 Physical Layer
 *         Using I<SUP>2</SUP>C For Communication
 *  \author Atmel Crypto Products
 *  \date  January 11, 2013
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


#include <avr/io.h>       // GPIO definitions
#include <util/twi.h>     // I2C definitions
#include <avr/power.h>    // definitions for power saving register
#include "i2c_phys.h"     // definitions and declarations for the hardware dependent I2C module
#include "Arduino.h"

/** \brief This function initializes and enables the I<SUP>2</SUP>C peripheral.
 * */
void i2c_enable(void)
{
#ifdef HAVE_PRR
	PRR &= ~_BV(PRTWI);            // Disable power saving.
#endif

#ifdef I2C_PULLUP
        digitalWrite(SDA, 1);
        digitalWrite(SCL, 1);
#endif

	TWBR = ((uint8_t) (((double) F_CPU / I2C_CLOCK - 16.0) / 2.0 + 0.5)); // Set the baud rate
}


/** \brief This function disables the I<SUP>2</SUP>C peripheral. */
void i2c_disable(void)
{
	TWCR = 0;                       // Disable TWI.
#ifdef HAVE_PRR
	PRR |= _BV(PRTWI);             // Enable power saving.
#endif
}


/** \brief This function creates a Start condition (SDA low, then SCL low).
 * \return status of the operation
 * */
uint8_t i2c_send_start(void)
{
	uint8_t timeout_counter = I2C_START_TIMEOUT;
	uint8_t i2c_status;

	TWCR = (_BV(TWEN) | _BV(TWSTA) | _BV(TWINT));
	do {
		if (timeout_counter-- == 0)
			return I2C_FUNCTION_RETCODE_TIMEOUT;
	} while ((TWCR & (_BV(TWINT))) == 0);

	i2c_status = TW_STATUS;
	if ((i2c_status != TW_START) && (i2c_status != TW_REP_START))
		return I2C_FUNCTION_RETCODE_COMM_FAIL;

	return I2C_FUNCTION_RETCODE_SUCCESS;
}


/** \brief This function creates a Stop condition (SCL high, then SDA high).
 * \return status of the operation
 * */
uint8_t i2c_send_stop(void)
{
	uint8_t timeout_counter = I2C_STOP_TIMEOUT;

	TWCR = (_BV(TWEN) | _BV(TWSTO) | _BV(TWINT));
	do {
		if (timeout_counter-- == 0)
			return I2C_FUNCTION_RETCODE_TIMEOUT;
	} while ((TWCR & _BV(TWSTO)) > 0);

	if (TW_STATUS == TW_BUS_ERROR)
		return I2C_FUNCTION_RETCODE_COMM_FAIL;

	return I2C_FUNCTION_RETCODE_SUCCESS;
}


/** \brief This function sends bytes to an I<SUP>2</SUP>C device.
 * \param[in] count number of bytes to send
 * \param[in] data pointer to tx buffer
 * \return status of the operation
 */
uint8_t i2c_send_bytes(uint8_t count, uint8_t *data)
{
	uint8_t timeout_counter;
	uint8_t twi_status;
	uint8_t i;

	for (i = 0; i < count; i++) {
		TWDR = *data++;
		TWCR = _BV(TWEN) | _BV(TWINT);

		timeout_counter = I2C_BYTE_TIMEOUT;
		do {
			if (timeout_counter-- == 0)
				return I2C_FUNCTION_RETCODE_TIMEOUT;
		} while ((TWCR & (_BV(TWINT))) == 0);

		twi_status = TW_STATUS;
		if ((twi_status != TW_MT_SLA_ACK)
					&& (twi_status != TW_MT_DATA_ACK)
					&& (twi_status != TW_MR_SLA_ACK))
			// Return error if byte got nacked.
			return I2C_FUNCTION_RETCODE_NACK;
	}

	return I2C_FUNCTION_RETCODE_SUCCESS;
}


/** \brief This function receives one byte from an I<SUP>2</SUP>C device.
 *
 * \param[out] data pointer to received byte
 * \return status of the operation
 */
uint8_t i2c_receive_byte(uint8_t *data)
{
	uint8_t timeout_counter = I2C_BYTE_TIMEOUT;

	// Enable acknowledging data.
	TWCR = (_BV(TWEN) | _BV(TWINT) | _BV(TWEA));
	do {
		if (timeout_counter-- == 0)
			return I2C_FUNCTION_RETCODE_TIMEOUT;
	} while ((TWCR & (_BV(TWINT))) == 0);

	if (TW_STATUS != TW_MR_DATA_ACK) {
		// Do not override original error.
		(void) i2c_send_stop();
		return I2C_FUNCTION_RETCODE_COMM_FAIL;
	}
	*data = TWDR;

	return I2C_FUNCTION_RETCODE_SUCCESS;
}


/** \brief This function receives bytes from an I<SUP>2</SUP>C device
 *         and sends a Stop.
 *
 * \param[in] count number of bytes to receive
 * \param[out] data pointer to rx buffer
 * \return status of the operation
 */
uint8_t i2c_receive_bytes(uint8_t count, uint8_t *data)
{
	uint8_t i;
	uint8_t timeout_counter;

	// Acknowledge all bytes except the last one.
	for (i = 0; i < count - 1; i++) {
		// Enable acknowledging data.
		TWCR = (_BV(TWEN) | _BV(TWINT) | _BV(TWEA));
		timeout_counter = I2C_BYTE_TIMEOUT;
		do {
			if (timeout_counter-- == 0)
				return I2C_FUNCTION_RETCODE_TIMEOUT;
		} while ((TWCR & (_BV(TWINT))) == 0);

		if (TW_STATUS != TW_MR_DATA_ACK) {
			// Do not override original error.
			(void) i2c_send_stop();
			return I2C_FUNCTION_RETCODE_COMM_FAIL;
		}
		*data++ = TWDR;
	}

	// Disable acknowledging data for the last byte.
	TWCR = (_BV(TWEN) | _BV(TWINT));
	timeout_counter = I2C_BYTE_TIMEOUT;
	do {
		if (timeout_counter-- == 0)
			return I2C_FUNCTION_RETCODE_TIMEOUT;
	} while ((TWCR & (_BV(TWINT))) == 0);

	if (TW_STATUS != TW_MR_DATA_NACK) {
		// Do not override original error.
		(void) i2c_send_stop();
		return I2C_FUNCTION_RETCODE_COMM_FAIL;
	}
	*data = TWDR;

	return i2c_send_stop();
}
