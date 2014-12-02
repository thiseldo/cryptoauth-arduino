#ifdef __cplusplus
extern "C" {
#endif
/** \file
 *  \brief ECC108 Library Return Code Definitions
 *  \author Atmel Crypto Products
 *  \date  October 21, 2013

* \copyright Copyright (c) 2014 Atmel Corporation. All rights reserved.
*
* \atmel_crypto_device_library_license_start
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
* \atmel_crypto_device_library_license_stop
 */

#ifndef ECC108_LIB_RETURN_CODES_H
#   define ECC108_LIB_RETURN_CODES_H

#include <stddef.h>                 // data type definitions


/** \defgroup atecc108_status Module 08: Library Return Codes
 *
@{ */

#define ECC108_SUCCESS              ((uint8_t)  0x00) //!< Function succeeded.
#define ECC108_CHECKMAC_FAILED		((uint8_t)  0xD1) //!< response status byte indicates CheckMac failure (status byte = 0x01)
#define ECC108_PARSE_ERROR          ((uint8_t)  0xD2) //!< response status byte indicates parsing error (status byte = 0x03)
#define ECC108_CMD_FAIL             ((uint8_t)  0xD3) //!< response status byte indicates command execution error (status byte = 0x0F)
#define ECC108_STATUS_CRC           ((uint8_t)  0xD4) //!< response status byte indicates CRC error (status byte = 0xFF)
#define ECC108_STATUS_UNKNOWN       ((uint8_t)  0xD5) //!< response status byte is unknown
#define ECC108_STATUS_ECC           ((uint8_t)  0xD6) //!< response status byte is ECC fault (status byte = 0x05)
#define ECC108_FUNC_FAIL            ((uint8_t)  0xE0) //!< Function could not execute due to incorrect condition / state.
#define ECC108_GEN_FAIL             ((uint8_t)  0xE1) //!< unspecified error
#define ECC108_BAD_PARAM            ((uint8_t)  0xE2) //!< bad argument (out of range, null pointer, etc.)
#define ECC108_INVALID_ID           ((uint8_t)  0xE3) //!< invalid device id, id not set
#define ECC108_INVALID_SIZE         ((uint8_t)  0xE4) //!< Count value is out of range or greater than buffer size.
#define ECC108_BAD_CRC              ((uint8_t)  0xE5) //!< incorrect CRC received
#define ECC108_RX_FAIL              ((uint8_t)  0xE6) //!< Timed out while waiting for response. Number of bytes received is > 0.
#define ECC108_RX_NO_RESPONSE       ((uint8_t)  0xE7) //!< Not an error while the Command layer is polling for a command response.
#define ECC108_RESYNC_WITH_WAKEUP   ((uint8_t)  0xE8) //!< Re-synchronization succeeded, but only after generating a Wake-up

#define ECC108_COMM_FAIL            ((uint8_t)  0xF0) //!< Communication with device failed. Same as in hardware dependent modules.
#define ECC108_TIMEOUT              ((uint8_t)  0xF1) //!< Timed out while waiting for response. Number of bytes received is 0.

/** @} */

#endif
#ifdef __cplusplus
}
#endif
