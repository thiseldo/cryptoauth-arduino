#ifdef __cplusplus
extern "C" {
#endif
// ----------------------------------------------------------------------------
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
 *  \brief ECCX08 Library Return Code Definitions
 *  \author Atmel Crypto Products
 *  \date  September 12, 2012
 */

#ifndef	ECCX08_LIB_RETURN_CODES_H
#	define	ECCX08_LIB_RETURN_CODES_H

#include <stddef.h>	// data type definitions


#define ECCX08_SUCCESS				((uint8_t)  0x00)	//!< Function succeeded.
#define ECCX08_CHECKMAC_FAILED		((uint8_t)  0xD1)	//!< response status byte indicates CheckMac failure
#define ECCX08_PARSE_ERROR			((uint8_t)  0xD2)	//!< response status byte indicates parsing error
#define ECCX08_CMD_FAIL				((uint8_t)  0xD3)	//!< response status byte indicates command execution error
#define ECCX08_STATUS_CRC			((uint8_t)  0xD4)	//!< response status byte indicates CRC error
#define ECCX08_STATUS_UNKNOWN		((uint8_t)  0xD5)	//!< response status byte is unknown
#define ECCX08_FUNC_FAIL			((uint8_t)  0xE0)	//!< Function could not execute due to incorrect condition / state.
#define ECCX08_GEN_FAIL				((uint8_t)  0xE1)	//!< unspecified error
#define ECCX08_BAD_PARAM			((uint8_t)  0xE2)	//!< bad argument (out of range, null pointer, etc.)
#define ECCX08_INVALID_ID			((uint8_t)  0xE3)	//!< invalid device id, id not set
#define ECCX08_INVALID_SIZE			((uint8_t)  0xE4)	//!< Count value is out of range or greater than buffer size.
#define ECCX08_BAD_CRC				((uint8_t)  0xE5)	//!< incorrect CRC received
#define ECCX08_RX_FAIL				((uint8_t)  0xE6)	//!< Timed out while waiting for response. Number of bytes received is > 0.
#define ECCX08_RX_NO_RESPONSE		((uint8_t)  0xE7)	//!< Not an error while the Command layer is polling for a command response.
#define ECCX08_RESYNC_WITH_WAKEUP	((uint8_t)  0xE8)	//!< re-synchronization succeeded, but only after generating a Wake-up

#define ECCX08_COMM_FAIL			((uint8_t)  0xF0)	//!< Communication with device failed. Same as in hardware dependent modules.
#define ECCX08_TIMEOUT				((uint8_t)  0xF1)	//!< Timed out while waiting for response. Number of bytes received is 0.


#endif
#ifdef __cplusplus
}
#endif	
