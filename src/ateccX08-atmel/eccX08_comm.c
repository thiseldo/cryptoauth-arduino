//         ATMEL Microcontroller Software Support  -  Colorado Springs, CO -
// ----------------------------------------------------------------------------
// DISCLAIMER:  THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
// DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
// OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
// EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// ----------------------------------------------------------------------------

/** \file
 *  \brief  Communication Layer of ECCX08 Library
 *  \author Atmel Crypto Products
 *  \date   September 12, 2012
 */
#include "eccX08_comm.h"					// definitions and declarations for the Communication module
#include "eccX08_lib_return_codes.h"		// declarations of function return codes

 

/** \brief This function calculates CRC.
 *
 * \param[in] length number of bytes in buffer
 * \param[in] data pointer to data for which CRC should be calculated
 * \param[out] crc pointer to 16-bit CRC
 */
void eccX08c_calculate_crc(uint8_t length, uint8_t *data, uint8_t *crc)
{
	uint8_t counter;
	uint16_t crc_register = 0;
	uint16_t polynom = 0x8005;
	uint8_t shift_register;
	uint8_t data_bit, crc_bit;
	
	for (counter = 0; counter < length; counter++)
	{
		for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1)
		{
			data_bit = (data[counter] & shift_register) ? 1 : 0;
			crc_bit = crc_register >> 15;
			crc_register <<= 1;
			if (data_bit != crc_bit)
				crc_register ^= polynom;
		}
	}
	
	crc[0] = (uint8_t) (crc_register & 0x00FF);
	crc[1] = (uint8_t) (crc_register >> 8);
}


/** \brief This function checks the consistency of a response.
 * \param[in] response pointer to response
 * \return status of the consistency check
 */
uint8_t eccX08c_check_crc(uint8_t *response)
{
	uint8_t crc[ECCX08_CRC_SIZE];
	uint8_t count = response[ECCX08_BUFFER_POS_COUNT];
	
	count -= ECCX08_CRC_SIZE;
	eccX08c_calculate_crc(count, response, crc);
	
	return (crc[0] == response[count] && crc[1] == response[count + 1])
		? ECCX08_SUCCESS : ECCX08_BAD_CRC;
}


/** \brief This function wakes up a ECCX08 device
 *         and receives a response.
 *  \param[out] response pointer to four-byte response
 *  \return status of the operation
 */
uint8_t eccX08c_wakeup(uint8_t *response)
{
	uint8_t ret_code = eccX08p_wakeup();
	if (ret_code != ECCX08_SUCCESS)
		return ret_code;
		
	ret_code = eccX08p_receive_response(ECCX08_RSP_SIZE_MIN, response);
	if (ret_code != ECCX08_SUCCESS)
		return ret_code;
		
	// Verify status response.
	if (response[ECCX08_BUFFER_POS_COUNT] != ECCX08_RSP_SIZE_MIN)
		ret_code = ECCX08_INVALID_SIZE;
	else if (response[ECCX08_BUFFER_POS_STATUS] != ECCX08_STATUS_BYTE_WAKEUP)
		ret_code = ECCX08_COMM_FAIL;
	else
	{
		if ((response[ECCX08_RSP_SIZE_MIN - ECCX08_CRC_SIZE] != 0x33)
				|| (response[ECCX08_RSP_SIZE_MIN + 1 - ECCX08_CRC_SIZE] != 0x43))
			ret_code = ECCX08_BAD_CRC;
	}
	if (ret_code != ECCX08_SUCCESS)
		delay_ms(ECCX08_COMMAND_EXEC_MAX);
		
	return ret_code;
}


/** \brief This function re-synchronizes communication.
 *
  Be aware that succeeding only after waking up the
  device could mean that it had gone to sleep and lost
  its TempKey in the process.\n
  Re-synchronizing communication is done in a maximum of
  three steps:
  <ol>
    <li>
      Try to re-synchronize without sending a Wake token.
      This step is implemented in the Physical layer.
    </li>
    <li>
      If the first step did not succeed send a Wake token.
    </li>
    <li>
      Try to read the Wake response.
    </li>
  </ol>
 *
 * \param[in] size size of response buffer
 * \param[out] response pointer to Wake-up response buffer
 * \return status of the operation
 */
uint8_t eccX08c_resync(uint8_t size, uint8_t *response)
{
	// Try to re-synchronize without sending a Wake token
	// (step 1 of the re-synchronization process).
	uint8_t ret_code = eccX08p_resync(size, response);
	if (ret_code == ECCX08_SUCCESS)
		return ret_code;
		
	// We lost communication. Send a Wake pulse and try
	// to receive a response (steps 2 and 3 of the
	// re-synchronization process).
	(void) eccX08p_sleep();
	ret_code = eccX08c_wakeup(response);
	
	// Translate a return value of success into one
	// that indicates that the device had to be woken up
	// and might have lost its TempKey.
	return (ret_code == ECCX08_SUCCESS ? ECCX08_RESYNC_WITH_WAKEUP : ret_code);
}


/** \brief This function runs a communication sequence:
 * Append CRC to tx buffer, send command, delay, and verify response after receiving it.
 *
 * The first byte in tx buffer must be the byte count of the packet.
 * If CRC or count of the response is incorrect, or a command byte got "nacked" (TWI),
 * this function requests re-sending the response.
 * If the response contains an error status, this function resends the command.
 *
 * \param[in] tx_buffer pointer to command
 * \param[in] rx_size size of response buffer
 * \param[out] rx_buffer pointer to response buffer
 * \param[in] execution_delay Start polling for a response after this many ms .
 * \param[in] execution_timeout polling timeout in ms
 * \return status of the operation
 */
uint8_t eccX08c_send_and_receive(uint8_t *tx_buffer, uint8_t rx_size, uint8_t *rx_buffer,
	uint8_t execution_delay, uint8_t execution_timeout)
{
	uint8_t ret_code = ECCX08_FUNC_FAIL;
	uint8_t ret_code_resync;
	uint8_t n_retries_send;
	uint8_t n_retries_receive;
	uint8_t i;
	uint8_t status_byte;
	uint8_t count = tx_buffer[ECCX08_BUFFER_POS_COUNT];
	uint8_t count_minus_crc = count - ECCX08_CRC_SIZE;
	uint16_t execution_timeout_us = (uint16_t) (execution_timeout * 1000) + ECCX08_RESPONSE_TIMEOUT;
	volatile uint16_t timeout_countdown;
	
	// Append CRC.
	eccX08c_calculate_crc(count_minus_crc, tx_buffer, tx_buffer + count_minus_crc);
	
	// Retry loop for sending a command and receiving a response.
	n_retries_send = ECCX08_RETRY_COUNT + 1;
	
	while ((n_retries_send-- > 0) && (ret_code != ECCX08_SUCCESS))
	{
		// Send command.
		ret_code = eccX08p_send_command(count, tx_buffer);
		if (ret_code != ECCX08_SUCCESS)
		{
			if (eccX08c_resync(rx_size, rx_buffer) == ECCX08_RX_NO_RESPONSE) {
				// The device seems to be dead in the water.
				//debugStream->println("eccX08c_send_and_receive 1");
				return ret_code;
			} else
				continue;
		}
		
		// Wait minimum command execution time and then start polling for a response.
		delay_ms(execution_delay);
		
		// Retry loop for receiving a response.
		n_retries_receive = ECCX08_RETRY_COUNT + 1;
		while (n_retries_receive-- > 0)
		{
			// Reset response buffer.
			for (i = 0; i < rx_size; i++)
				rx_buffer[i] = 0;
				
			// Poll for response.
			timeout_countdown = execution_timeout_us;
			do
			{
				// Send Dummy Write
				ret_code = eccX08p_send_command(0, NULL);
				timeout_countdown -= ECCX08_RESPONSE_TIMEOUT;
			} while ((timeout_countdown > ECCX08_RESPONSE_TIMEOUT) && (ret_code != ECCX08_SUCCESS));
			if (ret_code == ECCX08_SUCCESS)
			{
				ret_code = eccX08p_receive_response(rx_size, rx_buffer);
			}
			else
			{
				//Serial.println("eccX08c_send_and_receive 2");
// Likely place ECCX08_RX_NO_RESPONSE is being set
				ret_code = ECCX08_RX_NO_RESPONSE;
			}
			
			if (ret_code == ECCX08_RX_NO_RESPONSE)
			{
				// We did not receive a response. Re-synchronize and send command again.
				if (eccX08c_resync(rx_size, rx_buffer) == ECCX08_RX_NO_RESPONSE) {
					// The device seems to be dead in the water.
					//Serial.println("eccX08c_send_and_receive 3");
					return ret_code;
				} else
					break;
			}
			
			// Check whether we received a valid response.
			if (ret_code == ECCX08_INVALID_SIZE)
			{
				// We see 0xFF for the count when communication got out of sync.
				ret_code_resync = eccX08c_resync(rx_size, rx_buffer);
				if (ret_code_resync == ECCX08_SUCCESS)
					// We did not have to wake up the device. Try receiving response again.
					continue;
				if (ret_code_resync == ECCX08_RESYNC_WITH_WAKEUP)
					// We could re-synchronize, but only after waking up the device.
					// Re-send command.
					break;
				else
					// We failed to re-synchronize.
					return ret_code;
			}
			
			// We received a response of valid size. Check the consistency of the response.
			ret_code = eccX08c_check_crc(rx_buffer);
			if (ret_code == ECCX08_SUCCESS)
			{
				// Received valid response.
				if (rx_buffer[ECCX08_BUFFER_POS_COUNT] > ECCX08_RSP_SIZE_MIN)
					// Received non-status response. We are done.
					return ret_code;
					
				// Received status response.
				status_byte = rx_buffer[ECCX08_BUFFER_POS_STATUS];
				
				// Translate the three possible device status error codes
				// into library return codes.
				if (status_byte == ECCX08_STATUS_BYTE_PARSE)
					return ECCX08_PARSE_ERROR;
				if (status_byte == ECCX08_STATUS_BYTE_EXEC)
					return ECCX08_CMD_FAIL;
				if (status_byte == ECCX08_STATUS_BYTE_COMM)
				{
					// In case of the device status byte indicating a communication
					// error this function exits the retry loop for receiving a response
					// and enters the overall retry loop
					// (send command / receive response).
					ret_code = ECCX08_STATUS_CRC;
					break;
				}
				
				// Received status response from CheckMAC, DeriveKey, GenDig,
				// Lock, Nonce, Pause, UpdateExtra, or Write command.
				return ret_code;
			}
			else
			{
				// Received response with incorrect CRC.
				ret_code_resync = eccX08c_resync(rx_size, rx_buffer);
				if (ret_code_resync == ECCX08_SUCCESS)
					// We did not have to wake up the device. Try receiving response again.
					continue;
				if (ret_code_resync == ECCX08_RESYNC_WITH_WAKEUP)
					// We could re-synchronize, but only after waking up the device.
					// Re-send command.
					break;
				else
					// We failed to re-synchronize.
					return ret_code;
			} // block end of check response consistency
		} // block end of receive retry loop
	} // block end of send and receive retry loop
	
	return ret_code;
}
