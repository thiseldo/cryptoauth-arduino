/** \file
 *  \brief  Functions for I<SUP>2</SUP>C Physical Hardware Independent Layer of ATSHA204 Library
 *  \author Atmel Crypto Products
 *  \date   January 11, 2013
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
#define SHA204_GPIO_WAKEUP

#ifdef SHA204_GPIO_WAKEUP
#   include <avr/io.h>					    // GPIO definitions
#endif

#include "i2c_phys.h"                   // hardware dependent declarations for I2C
#include "sha204_physical.h"            // declarations that are common to all interface implementations
#include "sha204_lib_return_codes.h"    // declarations of function return codes
#include "timer_utilities.h"            // definitions for delay functions

/** \defgroup sha204_i2c Module 05: I2C Abstraction Module
 *
 * These functions and definitions abstract the I2C hardware. They implement the functions
 * declared in \ref sha204_physical.h.
@{ */


/** \brief I<SUP>2</SUP>C address used at ATSHA204 library startup. */
#define SHA204_I2C_DEFAULT_ADDRESS   ((uint8_t) 0xC8)


/** \brief This enumeration lists all packet types sent to a SHA204 device.
 *
 * The following byte stream is sent to a ATSHA204 I<SUP>2</SUP>C device:
 *    {I<SUP>2</SUP>C start} {I<SUP>2</SUP>C address} {word address} [{data}] {I<SUP>2</SUP>C stop}.
 * Data are only sent after a word address of value #SHA204_I2C_PACKET_FUNCTION_NORMAL.
 */
enum i2c_word_address {
	SHA204_I2C_PACKET_FUNCTION_RESET,  //!< Reset device.
	SHA204_I2C_PACKET_FUNCTION_SLEEP,  //!< Put device into Sleep mode.
	SHA204_I2C_PACKET_FUNCTION_IDLE,   //!< Put device into Idle mode.
	SHA204_I2C_PACKET_FUNCTION_NORMAL  //!< Write / evaluate data that follow this word address byte.
};


/** \brief This enumeration lists flags for I<SUP>2</SUP>C read or write addressing. */
enum i2c_read_write_flag {
	I2C_WRITE = (uint8_t) 0x00,  //!< write command flag
	I2C_READ  = (uint8_t) 0x01   //!< read command flag
};


//! I<SUP>2</SUP>C address is set when calling #sha204p_init or #sha204p_set_device_id.
static uint8_t device_address;


/** \brief This function sets the I<SUP>2</SUP>C address.
 *         Communication functions will use this address.
 *
 *  \param[in] id I<SUP>2</SUP>C address
 */
void sha204p_set_device_id(uint8_t id)
{
	device_address = id;
}


/** \brief This function initializes the hardware.
 */
void sha204p_init(void)
{
	i2c_enable();
	device_address = SHA204_I2C_DEFAULT_ADDRESS;
}

// todo Let the updateDistro script delete lines that refer to
// DEBUG_DIAMOND.
#ifndef DEBUG_DIAMOND
#   define DEBUG_DIAMOND
#endif
/** \brief This function generates a Wake-up pulse and delays.
 * \return status of the operation
 */
uint8_t sha204p_wakeup(void)
{
#ifndef SHA204_GPIO_WAKEUP
	// Generate wakeup pulse by writing a 0 on the I2C bus.
	uint8_t dummy_byte = 0;
	uint8_t i2c_status = i2c_send_start();
	if (i2c_status != I2C_FUNCTION_RETCODE_SUCCESS)
		return SHA204_COMM_FAIL;

	// To send eight zero bits it takes 10E6 / I2C clock * 8 us.
	delay_10us(SHA204_WAKEUP_PULSE_WIDTH - (uint8_t) (1000000.0 / 10.0 / I2C_CLOCK * 8.0));

	// We have to send at least one byte between an I2C Start and an I2C Stop.
	(void) i2c_send_bytes(1, &dummy_byte);
	i2c_status = i2c_send_stop();
	if (i2c_status != I2C_FUNCTION_RETCODE_SUCCESS)
		return SHA204_COMM_FAIL;
#else
	// Generate wakeup pulse by disabling the I2C peripheral and
	// pulling SDA low. The I2C peripheral gets automatically
	// re-enabled when calling i2c_send_start().
	TWCR = 0;           // Disable I2C.
	DDRD |= _BV(PD1);   // Set SDA as output.
	PORTD &= ~_BV(PD1); // Set SDA low.
#ifndef DEBUG_DIAMOND
	delay_10us(SHA204_WAKEUP_PULSE_WIDTH);
#else	
	delay_10us(10);
#endif	
	PORTD |= _BV(PD1);  // Set SDA high.
#endif

	delay_ms(SHA204_WAKEUP_DELAY);

	return SHA204_SUCCESS;
}


/** \brief This function creates a Start condition and sends the
 * I<SUP>2</SUP>C address.
 * \param[in] read #I2C_READ for reading, #I2C_WRITE for writing
 * \return status of the I<SUP>2</SUP>C operation
 */
static uint8_t sha204p_send_slave_address(uint8_t read)
{
	uint8_t sla = device_address | read;
	uint8_t ret_code = i2c_send_start();
	if (ret_code != I2C_FUNCTION_RETCODE_SUCCESS)
		return ret_code;

	ret_code = i2c_send_bytes(1, &sla);

	if (ret_code != I2C_FUNCTION_RETCODE_SUCCESS)
		(void) i2c_send_stop();

	return ret_code;
}


/** \brief This function sends a I<SUP>2</SUP>C packet enclosed by
 *         a I<SUP>2</SUP>C start and stop to the device.
 *
This function combines a I<SUP>2</SUP>C packet send sequence that
is common to all packet types. Only if word_address is
#I2C_PACKET_FUNCTION_NORMAL, count and buffer parameters are
expected to be non-zero.
 * @param[in] word_address packet function code listed in #i2c_word_address
 * @param[in] count number of bytes in data buffer
 * @param[in] buffer pointer to data buffer
 * @return status of the operation
 */
static uint8_t sha204p_i2c_send(uint8_t word_address, uint8_t count, uint8_t *buffer)
{
	uint8_t i2c_status = sha204p_send_slave_address(I2C_WRITE);
	if (i2c_status != I2C_FUNCTION_RETCODE_SUCCESS)
		return SHA204_COMM_FAIL;

	i2c_status = i2c_send_bytes(1, &word_address);
	if (i2c_status != I2C_FUNCTION_RETCODE_SUCCESS)
		return SHA204_COMM_FAIL;

	if (count == 0) {
		// We are done for packets that are not commands (Sleep, Idle, Reset).
		(void) i2c_send_stop();
		return SHA204_SUCCESS;
	}

	i2c_status = i2c_send_bytes(count, buffer);

	(void) i2c_send_stop();

	if (i2c_status != I2C_FUNCTION_RETCODE_SUCCESS)
		return SHA204_COMM_FAIL;
	else
		return SHA204_SUCCESS;
}


/** \brief This function sends a command to the device.
 * \param[in] count number of bytes to send
 * \param[in] command pointer to command buffer
 * \return status of the operation
 */
uint8_t sha204p_send_command(uint8_t count, uint8_t *command)
{
	return sha204p_i2c_send(SHA204_I2C_PACKET_FUNCTION_NORMAL, count, command);
}


/** \brief This function puts the device into idle state.
 * \return status of the operation
 */
uint8_t sha204p_idle(void)
{
	return sha204p_i2c_send(SHA204_I2C_PACKET_FUNCTION_IDLE, 0, NULL);
}


/** \brief This function puts the device into low-power state.
 *  \return status of the operation
 */
uint8_t sha204p_sleep(void)
{
	return sha204p_i2c_send(SHA204_I2C_PACKET_FUNCTION_SLEEP, 0, NULL);
}


/** \brief This function resets the I/O buffer of the device.
 * \return status of the operation
 */
uint8_t sha204p_reset_io(void)
{
	return sha204p_i2c_send(SHA204_I2C_PACKET_FUNCTION_RESET, 0, NULL);
}


/** \brief This function receives a response from the device.
 *
 * \param[in] size size of rx buffer
 * \param[out] response pointer to rx buffer
 * \return status of the operation
 */
uint8_t sha204p_receive_response(uint8_t size, uint8_t *response)
{
	uint8_t count;

	// Address the device and indicate that bytes are to be read.
	uint8_t i2c_status = sha204p_send_slave_address(I2C_READ);
	if (i2c_status != I2C_FUNCTION_RETCODE_SUCCESS) {
		// Translate error so that the Communication layer
		// can distinguish between a real error or the
		// device being busy executing a command.
		if (i2c_status == I2C_FUNCTION_RETCODE_NACK)
			i2c_status = SHA204_RX_NO_RESPONSE;

		return i2c_status;
	}

	// Receive count byte.
	i2c_status = i2c_receive_byte(response);
	if (i2c_status != I2C_FUNCTION_RETCODE_SUCCESS)
		return SHA204_COMM_FAIL;

	count = response[SHA204_BUFFER_POS_COUNT];
	if ((count < SHA204_RSP_SIZE_MIN) || (count > size)) {
		(void) i2c_send_stop();
		return SHA204_INVALID_SIZE;
	}		

	i2c_status = i2c_receive_bytes(count - 1, &response[SHA204_BUFFER_POS_DATA]);

	if (i2c_status != I2C_FUNCTION_RETCODE_SUCCESS)
		return SHA204_COMM_FAIL;
	else
		return SHA204_SUCCESS;
}


/** \brief This function resynchronizes communication.
 *
 * Parameters are not used for I<SUP>2</SUP>C.\n
 * Re-synchronizing communication is done in a maximum of three steps
 * listed below. This function implements the first step. Since
 * steps 2 and 3 (sending a Wake-up token and reading the response)
 * are the same for I<SUP>2</SUP>C and SWI, they are
 * implemented in the communication layer (#sha204c_resync).
  <ol>
     <li>
       To ensure an IO channel reset, the system should send
       the standard I2C software reset sequence, as follows:
       <ul>
         <li>a Start condition</li>
         <li>nine cycles of SCL, with SDA held high</li>
         <li>another Start condition</li>
         <li>a Stop condition</li>
       </ul>
       It should then be possible to send a read sequence and
       if synchronization has completed properly the ATSHA204 will
       acknowledge the device address. The chip may return data or
       may leave the bus floating (which the system will interpret
       as a data value of 0xFF) during the data periods.\n
       If the chip does acknowledge the device address, the system
       should reset the internal address counter to force the
       ATSHA204 to ignore any partial input command that may have
       been sent. This can be accomplished by sending a write
       sequence to word address 0x00 (Reset), followed by a
       Stop condition.
     </li>
     <li>
       If the chip does NOT respond to the device address with an ACK,
       then it may be asleep. In this case, the system should send a
       complete Wake token and wait t_whi after the rising edge. The
       system may then send another read sequence and if synchronization
       has completed the chip will acknowledge the device address.
     </li>
     <li>
       If the chip still does not respond to the device address with
       an acknowledge, then it may be busy executing a command. The
       system should wait the longest TEXEC and then send the
       read sequence, which will be acknowledged by the chip.
     </li>
  </ol>
 * \param[in] size size of rx buffer
 * \param[out] response pointer to response buffer
 * \return status of the operation
 */
uint8_t sha204p_resync(uint8_t size, uint8_t *response)
{
	uint8_t nine_clocks = 0xFF;
	uint8_t ret_code = i2c_send_start();

	// Do not evaluate the return code that most likely indicates error,
	// since nine_clocks is unlikely to be acknowledged.
	(void) i2c_send_bytes(1, &nine_clocks);

	// Send another Start. The function sends also one byte,
	// the I2C address of the device, because I2C specification
	// does not allow sending a Stop right after a Start condition.
	ret_code = sha204p_send_slave_address(I2C_READ);

	// Send only a Stop if the above call succeeded.
	// Otherwise the above function has sent it already.
	if (ret_code == I2C_FUNCTION_RETCODE_SUCCESS)
		ret_code = i2c_send_stop();

	// Return error status if we failed to re-sync.
	if (ret_code != I2C_FUNCTION_RETCODE_SUCCESS)
		return SHA204_COMM_FAIL;

	// Try to send a Reset IO command if re-sync succeeded.
	return sha204p_reset_io();
}

/** @} */
