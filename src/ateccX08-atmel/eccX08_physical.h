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
 *  \brief  Definitions and Prototypes for Physical Layer Interface of ECCX08 Library
 *  \author Atmel Crypto Products
 *  \date 	May 3, 2013
 */
#ifndef	ECCX08_PHYSICAL_H
#	define	ECCX08_PHYSICAL_H

#include <stdint.h>			// data type definitions

#include "eccX08_config.h"	// configuration values


#define ECCX08_RSP_SIZE_MIN			((uint8_t)  4)				//!< minimum number of bytes in response
#define ECCX08_RSP_SIZE_64			((uint8_t) 67)				//!< size of response packet containing 64 bytes data
#define ECCX08_RSP_SIZE_32			((uint8_t) 35)				//!< size of response packet containing 32 bytes data
#define ECCX08_RSP_SIZE_MAX			((uint8_t) 75)				//!< maximum size of response packet

#define ECCX08_BUFFER_POS_COUNT		(0)							//!< buffer index of count byte in command or response
#define ECCX08_BUFFER_POS_DATA		(1)							//!< buffer index of data in response

//! width of Wakeup pulse in 10 us units
#define ECCX08_WAKEUP_PULSE_WIDTH	(uint8_t) (12.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5)

//! delay between Wakeup pulse and communication in 10 us units
#define ECCX08_WAKEUP_DELAY			(uint8_t) (100.0 * CPU_CLOCK_DEVIATION_POSITIVE + 0.5)


uint8_t	eccX08p_send_command(uint8_t count, uint8_t *command);
uint8_t	eccX08p_receive_response(uint8_t size, uint8_t *response);
void	eccX08p_init(void);
void	eccX08p_i2c_set_spd(uint32_t spd_in_khz);
void	eccX08p_set_device_id(uint8_t id);
uint8_t	eccX08p_wakeup(void);
uint8_t	eccX08p_idle(void);
uint8_t	eccX08p_sleep(void);
uint8_t	eccX08p_reset_io(void);
uint8_t	eccX08p_resync(uint8_t size, uint8_t *response);

#endif
#ifdef __cplusplus
}
#endif
