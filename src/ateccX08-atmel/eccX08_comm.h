#ifdef __cplusplus
extern "C" {
#endif
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
 *  \brief  Definitions and Prototypes for Communication Layer of ECCX08 Library
 *  \author Atmel Crypto Products
 *  \date   September 12, 2012
 */
#ifndef	ECCX08_COMM_H
#	define	ECCX08_COMM_H

#include <stddef.h>				// data type definitions

#include "eccX08_physical.h"	// declarations that are common to all interface implementations


//! maximum command delay
#define ECCX08_COMMAND_EXEC_MAX		((uint8_t) (120.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5))

//! minimum number of bytes in command (from count byte to second CRC byte)
#define ECCX08_CMD_SIZE_MIN			((uint8_t) 7)

//! maximum size of command packet (Verify)
#define ECCX08_CMD_SIZE_MAX			((uint8_t) 4 * 36 + 7)

//! number of CRC bytes
#define ECCX08_CRC_SIZE				((uint8_t) 2)

//! buffer index of status byte in status response
#define ECCX08_BUFFER_POS_STATUS	(1)

//! buffer index of first data byte in data response
#define ECCX08_BUFFER_POS_DATA		(1)

//! status byte after wake-up
#define ECCX08_STATUS_BYTE_WAKEUP	((uint8_t) 0x11)

//! command parse error
#define ECCX08_STATUS_BYTE_PARSE	((uint8_t) 0x03)

//! command execution error
#define ECCX08_STATUS_BYTE_EXEC		((uint8_t) 0x0F)

//! communication error
#define ECCX08_STATUS_BYTE_COMM		((uint8_t) 0xFF)


void	eccX08c_calculate_crc(uint8_t length, uint8_t *data, uint8_t *crc);
uint8_t	ecc108c_check_crc(uint8_t *response);
uint8_t	eccX08c_wakeup(uint8_t *response);
uint8_t	ecc108c_resync(uint8_t size, uint8_t *response);
uint8_t	eccX08c_send_and_receive(uint8_t *tx_buffer, uint8_t rx_size, uint8_t *rx_buffer, uint8_t execution_delay, uint8_t execution_timeout);

#endif
#ifdef __cplusplus
}
#endif
