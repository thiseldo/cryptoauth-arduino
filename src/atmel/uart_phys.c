/** \file
 *  \brief Physical Layer Functions of ATSHA204 Library When Using UART
 *
 *         This module supports most of ATmega and all ATXmega AVR microcontrollers.
 *         http://www.atmel.com/dyn/products/param_table.asp?family_id=607&OrderBy=part_no&Direction=ASC
 *
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

#include "swi_phys.h"        // hardware dependent declarations for SWI
#include "uart_config.h"     // UART definitions
#include "avr_compatible.h"  // translates generic AVR UART macros into specific ones

/** \defgroup atsha204_swi_uart Module 13: UART Interface
 *
 * This module implements the single-wire interface using a UART
 * micro-controller peripheral.
*/

/** \brief This UART function is a dummy to satisfy the SWI module interface.
 *
 *  \param[in] id not used in this UART module, only used in SWI bit-banging module
 *                To be able to talk to two devices (client or host) sending a 
 *                Pause flag is required. Please refer to the data sheet.
 */
void swi_set_device_id(uint8_t id) {
}


/** \brief This UART function initializes the hardware.
 */
void swi_enable(void) {
	UCSRA = _BV(U2X);

	// According to the data sheet, the formula should be the one below
	// that is commented out. But what is missing in the data sheet is
	// rounding the result.
	// In this implementation for an F_CPU = 16 MHz we get UBRRL = 7.68.
	// But according to the data sheet, we need to load 8, not 7, to achieve
	// a baudrate of 230400 with an error of -3.5%. Therefore, we have to
	// add 1 to the result before type casting.
	// UBRRL = (uint8_t) (F_CPU / (8UL * BAUD_RATE) - 1UL);
	UBRRL = (uint8_t) (F_CPU / (8UL * BAUD_RATE));

	// When using a UART for the SWI, we configure
	// the UART with one start bit, seven character
	// bits, and one stop bit, a total of nine bits.
	// This leads to a bit width of
	//    t(bit) = 9 / 230400 = 39.0625 us.
	UCSRC = _BV(UCSZ11);

	// Disable rx and tx interrupt.
	UCSRB &= ~(_BV(TXCIE) | _BV(RXCIE));

#ifdef DEBUG_UART
	DEBUG_PORT_DDR |= _BV(DEBUG_BIT);
	DEBUG_LOW;
#endif
}


/** \brief This UART function sets the signal pin using GPIO.
 *
	It is used to generate a Wake-up pulse.<BR>
	Another way to generate a Wake-up pulse is using the UART
	at half the communication baud rate and sending a 0.
	Keeping the baud rate at 230400 would only produce
	the signal wire going low for 34.7 us
	when sending a data byte of 0 that causes the signal wire
	being low for eight bits (start bit and seven data bits).
	Configuring the UART for half the baud rate and sending
	a 0 produces a long enough Wake-up pulse of 69.4 us.<BR>
	The fact that a hardware independent Physical layer above
	this hardware dependent layer delays for Wake-pulse width
	after calling this function would only add this delay to the
	much longer delay of 3 ms after the Wake-up pulse.
	With other words, by not using GPIO for the generation of
	a Wake-up pulse, we add only 69.4 us to the delay of
	3000 us after the Wake-up pulse.<BR>
	Implementing a Wake-up pulse generation using the UART
	would introduce a slight design flaw though since this module
	would now "know" something about the width of the Wake-up pulse.
	We could add a function that sets the baud rate and
	sends a 0, but that would add at least 150 bytes of code.
 * \param[in] is_high 0: set signal low, otherwise set signal high
 */
void swi_set_signal_pin(uint8_t is_high)
{
	// Turn off transmit and receive.
	UCSRB &= ~(_BV(RXEN) | _BV(TXEN));

	UART_GPIO_DDR |= UART_GPIO_PIN_TX;

	if (is_high > 0)
		UART_GPIO_OUT |= UART_GPIO_PIN_TX;
	else
		UART_GPIO_OUT &= ~UART_GPIO_PIN_TX;
}


/** \brief This UART function sends bytes to an SWI device.
 * \param[in] count number of bytes to send
 * \param[in] buffer pointer to transmit buffer
 * \return status of the operation
 */
uint8_t swi_send_bytes(uint8_t count, uint8_t *buffer)
{
	uint8_t i, bit_mask, timeout, rx_tx_delay = RX_TX_DELAY;

	UCSRB &= ~_BV(RXEN);            // Turn off receive.
	UCSRB |= _BV(TXEN);             // Turn on transmit.

	while (rx_tx_delay--);

	for (i = 0; i < count; i++) {
		DEBUG_HIGH;
		for (bit_mask = 1; bit_mask > 0; bit_mask <<= 1) {
			timeout = BIT_TIMEOUT;
			while ((UCSRA & _BV(UDRE)) == 0) {
				if (timeout-- == 0) {
					UCSRA |= _BV(TXC);
					return SWI_FUNCTION_RETCODE_TIMEOUT;
				}
			}

			// Create a start pulse only ("zero" bit)
			// or a start pulse and a zero pulse ("one" bit).
			// The zero pulse is placed at UDR bit 2 (lsb first).
			UDR = (bit_mask & buffer[i]) ? 0x7F : 0x7D;
		}
		DEBUG_LOW;
	}
	// Wait until last byte is sent.
	// This should not take longer than bit time (39 us).
	// The polling loop takes around 1 us on an 8-bit AVR clocking at 16 MHz.
	timeout = BIT_TIMEOUT;
	while ((UCSRA & _BV(TXC)) == 0) {
		if (timeout-- == 0)
			return SWI_FUNCTION_RETCODE_TIMEOUT;
	}

	// We must manually clear transmit complete flag if not using interrupts
	// by writing a logic one to it!
	UCSRA |= _BV(TXC);

	return SWI_FUNCTION_RETCODE_SUCCESS;
}


/** \brief This UART function sends one byte to an SWI device.
 * \param[in] value byte to send
 * \return status of the operation
 */
uint8_t swi_send_byte(uint8_t value)
{
	return swi_send_bytes(1, &value);
}


/** \brief This UART function receives bytes from an SWI device.
 *  \param[in] count number of bytes to receive
 *  \param[out] buffer pointer to receive buffer
 * \return status of the operation
 */
uint8_t swi_receive_bytes(uint8_t count, uint8_t *buffer) {
	uint8_t i, bit_mask, bit_data, timeout;

	// Turn off transmit. The transmitter will not turn off until transmit is complete.
	UCSRB &= ~_BV(TXEN);

	// Disable pull-up resistor.
	UART_GPIO_DDR &= ~(UART_GPIO_PIN_TX | UART_GPIO_PIN_TX);
	UART_GPIO_OUT &= ~(UART_GPIO_PIN_TX | UART_GPIO_PIN_TX);

	// Turn on receive.
	UCSRB |= _BV(RXEN);

	DEBUG_HIGH;

	for (i = 0; i < count; i++) {
		buffer[i] = 0;
		for (bit_mask = 1; bit_mask > 0; bit_mask <<= 1) {
			timeout = BIT_TIMEOUT;
			while (bit_is_clear(UCSRA, RXC)) {
				if (timeout-- == 0)
					return (i == 0 ? SWI_FUNCTION_RETCODE_TIMEOUT : SWI_FUNCTION_RETCODE_RX_FAIL);
			}
			bit_data = UDR;
			// If the device sends a "one" bit, UDR bits 1 to 6 are set (0x7E).
			// LSB comes first. Reversing 0x7E results in 0x7E.
			if ((bit_data & 0x7E) == 0x7E)
				// Received "one" bit.
				buffer[i] |= bit_mask;
		}
	}
	DEBUG_LOW;

	return SWI_FUNCTION_RETCODE_SUCCESS;
}

/** @} */
