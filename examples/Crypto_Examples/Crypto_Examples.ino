/**
 * Crypto_Example sketch for demonstrating some of the functionality of the
 * Atmel ATECC508A Crypto Authentication chips.
 * This uses a how a simple data driven menu system.
 * Features demonstrated:
 *  Get basic info from chip, Serial number, key types and lock states
 *  Personalise the chip
 *  Get a random number
 *  Generate a private ECC key in a keyslot
 *  Get the private keys public key
 *  Lock a key slot
 *  Generate a SHA256 hash for a data string
 *  Generate a digital signature for a data string
 *  Verify a digital signature
 *
 * (c) 2015 Andrew D Lindsay, Thing Innovations
 *
 */

#include <Arduino.h>
#include <cryptoauth.h>

// If using a ATECC508A then include this define, if ATECC108A then comment out
// It only affects the defaults on some of the personalisation data.
#define USE_ATECC508


// Function declarations for use in menu
void menuGetInfo();
void menuPersonalize();
void menuGetRandom();
void menuGenPrivateKey();
void menuGetPublicKey();
void menuLockKeySlot();
void menuHashData();
void menuSignData();
void menuVerifyData();

// Define our menu, number of items then list of menu options and functions to call
#define NUM_MENU_ITEM 9
// Maximum length of a menu option text is 16 characters, 17 used to include termination character
static char menu_items[NUM_MENU_ITEM][17] = {
  // -----------------
  "Chip Info",
  "Personalize",
  "Random Number",
  "Gen Private Key",
  "Get Public Key",
  "Lock key slot",
  "Hash Data",
  "Sign Data",
  "Verify Data"
};

// Array of functions. This makes coding the menu actions easy and more options can be added without code changes.
void (*menu_funcs[NUM_MENU_ITEM])(void) = {
  menuGetInfo,
  menuPersonalize,
  menuGetRandom,
  menuGenPrivateKey,
  menuGetPublicKey,
  menuLockKeySlot,
  menuHashData,
  menuSignData,
  menuVerifyData
};

// Object for ATECC508A
AtEccX08 ecc = AtEccX08();

// Configuration zone is set with 16 ECC 256 key storage
// Configure for your own device usage, see Datasheet Section 2.2
// Specific key uses can be configured. Defaults here are for 16 ECC
// keys that can be used to store provate keys for Sign/MAC use.
// First 16 bytes are read only and are not included to save some space
// TODO: Move to Flash
static const uint8_t config_zone[]  =
{
  /* 0-15 write only, not included, shown for reference
  0x01, 0x23, 0x00, 0x00, // 0-3 SN[0:3] RO
  0x00, 0x00, 0x00, 0x00, // 4-7 RevNum RO
  0x00, 0x00, 0x00, 0x00, 0xEE, // 8-12 SN[4:8]
  0xC0, // 13 Reserved
  0xA7, // 14 I2C Enable
  0x00, // 15 Reserved
  */
  0xC0, // 16 I2C Address
  0x00, // 17 Reserved
  0xAA, // 18 OTP Mode
  0x00, // 19 Chip Mode
  0x81, 0xA0, // 20-21 SlotConfig 0, External Sig, Is Secret, Never write, GenKey can write random keys
  0x81, 0xA0, // 22-23 SlotConfig 1
  0x81, 0xA0, // 24-25 SlotConfig 2
  0x81, 0xA0, // 26-27 SlotConfig 3
  0x81, 0xA0, // 28-29 SlotConfig 4
  0x81, 0xA0, // 30-31 SlotConfig 5
  0x81, 0xA0, // 32-33 SlotConfig 6
  0x81, 0xA0, // 34-35 SlotConfig 7
  0x81, 0xA0, // 36-37 SlotConfig 8
  0x81, 0xA0, // 38-39 SlotConfig 9
  0x81, 0xA0, // 40-41 SlotConfig 10
  0x81, 0xA0, // 42-43 SlotConfig 11
  0x81, 0xA0, // 44-45 SlotConfig 12
  0x81, 0xA0, // 46-47 SlotConfig 13
  0x81, 0xA0, // 48-49 SlotConfig 14
  0x81, 0xA0, // 50-51 SlotConfig 15
#ifdef USE_ATECC508
  // ATECC508A
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 52-59 Counter[0]
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 60-67 Counter[1]
#else
  // ATECC108A
  0xFF, 0x00, // 52-53 UseFlag, UpdateCount Key 0
  0xFF, 0x00, // 54-55 UseFlag, UpdateCount Key 1
  0xFF, 0x00, // 56-57 UseFlag, UpdateCount Key 2
  0xFF, 0x00, // 58-59 UseFlag, UpdateCount Key 3
  0xFF, 0x00, // 60-61 UseFlag, UpdateCount Key 4
  0xFF, 0x00, // 62-63 UseFlag, UpdateCount Key 5
  0xFF, 0x00, // 64-65 UseFlag, UpdateCount Key 6
  0xFF, 0x00, // 66-67 UseFlag, UpdateCount Key 7
#endif
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // 68-83 Last KeyUse
  0x00, // 84 UserExtra
  0x09, // 85 Selector
  0x00, // 86 LockValue
  0x00, // 87 LockConfig
  0xFF, 0xFF, // 88-89 SlotLocked
  0x00, 0x00, // 90-91 RFU
  0x00, 0x00, 0x00, 0x00, // 92-95 X509format -
  // 0011 0011 0000 0000
  0x33, 0x00, //  96-97 KeyConfig slot 0, Private, can generate Public key, P256 NIST ECC key, Lockable,
  //                                      Random nonce Not required, No prior auth required
  0x33, 0x00, //  98-99  KeyConfig slot 1
  0x33, 0x00, // 100-101 KeyConfig slot 2
  0x33, 0x00, // 102-103 KeyConfig slot 3
  0x33, 0x00, // 104-105 KeyConfig slot 4
  0x33, 0x00, // 106-107 KeyConfig slot 5
  0x33, 0x00, // 108-109 KeyConfig slot 6
  0x33, 0x00, // 110-111 KeyConfig slot 7
  0x3C, 0x00, // 112-113 KeyConfig slot 8, Non ECC keys
  0x3C, 0x00, // 114-115 KeyConfig slot 9
  0x3C, 0x00, // 116-117 KeyConfig slot 10
  0x3C, 0x00, // 118-119 KeyConfig slot 11
  0x3C, 0x00, // 120-121 KeyConfig slot 12
  0x3C, 0x00, // 122-123 KeyConfig slot 13
  0x3C, 0x00, // 124-125 KeyConfig slot 14
  0x3C, 0x00  // 126-127 KeyConfig slot 15
};

// convert to ascii to see what this says - put customised message
// http://www.asciitohex.com/
// http://string-functions.com/hex-string.aspx
// 64 bytes
// CRYPTRONIX CRYPTOAUTH ARDUINO LIBRARY V: 0.2 ThingInnovations.
static const uint8_t otp_zone[] =
{
  0x43, 0x52, 0x59, 0x50, 0x54, 0x52, 0x4f, 0x4e,
  0x49, 0x58, 0x20, 0x43, 0x52, 0x59, 0x50, 0x54,
  0x4f, 0x41, 0x55, 0x54, 0x48, 0x20, 0x41, 0x52,
  0x44, 0x55, 0x49, 0x4e, 0x4f, 0x20, 0x4c, 0x49,
  0x42, 0x52, 0x41, 0x52, 0x59, 0x20, 0x56, 0x3a,
  0x20, 0x30, 0x2e, 0x32, 0x20, 0x54, 0x68, 0x69,
  0x6e, 0x67, 0x49, 0x6e, 0x6e, 0x6f, 0x76, 0x61,
  0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x00, 0x00
};

// Keep a record of key slot state for use in error reporting
uint16_t slotLockState = 0xFF;  // Same as SlotLocked, bit per slot, 0=Locked
uint16_t eccKeyState = 0x00;    // Bit per slot, 1 = ECC Key.

// Utility functions

/** displayData - Display packet data in hex.
 *  @param rspPtr packet response pointer
 *  @param bufLen Length of data to display
 */
void displayData( const uint8_t *rspPtr, uint8_t bufLen ) {
  const uint8_t *bufPtr = rspPtr;
  // Display serial number and add to serialNum buffer
  for (int i = 0; i < bufLen; i++ ) {
    if ( bufPtr[i] < 16 ) Serial.print(F("0"));
    Serial.print(bufPtr[i], HEX);
  }
  Serial.println();
}

/** hexify - Convert a character string to its hex representation. Each char becomes
 *  2 hex chars.
 *  @param str - the string pointed to
 *  @param hex - Hex output buffer
 *  @param len -
 */
void hexify(const char *str, const uint8_t *hex, unsigned int len) {
  int i;

  Serial.write(str);
  for (i = 0; i < len; i++)  {
    static char tmp[4] = {};
    sprintf(tmp, "%02X", hex[i]);
    Serial.write(tmp);
  }

//  Serial.write("\n");
  Serial.println();

}

/** displayResponse - take a low I2C driver response code and display
 *  meaningfull message. Checks key slot flags if needed
 *  @param respCode - response code received from driver
 *  @param keyNum - Key number of the slot being worked on
 */
void displayResponse( uint8_t respCode, uint8_t keyNum ) {
  switch (respCode) {
    case 0xD2:
      Serial.print(F("CMD Fail - Parse Error"));
      break;
    case 0xD3:
      Serial.print(F("CMD Fail - "));
      Serial.print(isSlotLocked(keyNum) ? F("Slot locked") : F("No Private key") );
      break;
    case 0xE7:
      Serial.print(F("No Response"));
      break;
    default:
      Serial.print(respCode, HEX);
  }
  Serial.println();
}

/** isSlotLocked - use previously saved flags to test if a key slot has been locked.
 * @param keyNum - Key nubmer to check
 * @return true/false indicating lock state of key
 */
boolean isSlotLocked( uint8_t keyNum ) {
  return slotLockState & (1 << keyNum ) ? false : true;
}

/** displayLockState - display the lock state for the specified zone
 * @param zone - the zone to display, 0 for Config Zone, 1 for Data Zone
 */
void displayLockState( uint8_t zone ) {
  Serial.print( ecc.is_locked( zone ) ? F("") : F(" not" ));
  Serial.println(F(" Locked"));
}


// User Interface functions

/** selectKey - helper function for entering a key number, displays prompt
 *  @return the key number, 0 - 15
 */
int selectKey() {
  Serial.print(F("Key Number [0-15] "));
  return getKeyNum();
}

/** getKeyNum - read the key number from serial input.
 *  @return the selected key number 0 - 15
 */
int getKeyNum() {
  int keyNum = 0;
  consumeInput();
  boolean lineEndFound = false;
  while ( !lineEndFound ) {
    if ( Serial.available() ) {
      int inDigit = Serial.read();
      if ( inDigit >= '0' && inDigit <= '9' ) {
        Serial.print( (char)inDigit );
        keyNum *= 10;
        keyNum += (inDigit - '0');
      } else if ( inDigit == '\n' || inDigit == '\r' )
        lineEndFound = true;
    }
  }
  Serial.println();
  return keyNum;
}

/** getConfirm - Get response to confirmation question, y or Y for true response
 *  @return true for Y or y entered, false for anything else.
 */
boolean getConfirm() {
  boolean confirm = false;
  consumeInput();
  while ( 1 ) {
    if ( Serial.available()) {
      int inByte = Serial.read();
      Serial.write(inByte);
      if ( inByte == 'Y' || inByte == 'y' )
        return true;
      else
        return false;
    }
  }
  return false;
}

/** consumeInput - general function to consume any waiting characters in input buffer
 *
 */
void consumeInput() {
  while ( Serial.available() ) {
    Serial.read();
  }
}

/** getInputData - Read a number of characters from inout stream and store in
 * output buffer. Ends when maxLen characters entered or CR or LF entered.
 * Assumes data buffer is of sufficient length to take received characters.
 * @param data - Where to store the entered characters
 * @param maxLen - Maximum number of chars to receive
 */
void getInputData( uint8_t *data, unsigned int maxLen ) {
  int len = 0;
  uint8_t *dPtr = data;
  uint8_t value = 0;
  boolean lineEndFound = false;
  consumeInput();
  while ( len < maxLen && !lineEndFound) {
    if ( Serial.available() ) {
      int inByte = Serial.read();
      Serial.write(inByte);
      if ( inByte == '\n' || inByte == '\r' ) {
        lineEndFound = true;
        inByte = 0;
      }
      *dPtr++ = inByte;
    }
  }
  Serial.println();
}

/** getHexInputData - Read a number of characters from inout stream and store in
 * output buffer. 2 input characters become 1 data value as it reads hex values.
 * Ends when requiredLen data values have been entered.
 * Assumes data buffer is of sufficient length to take received characters.
 * @param data - Where to store the entered characters
 * @param maxLen - Maximum number of chars to receive
 */
void getHexInputData( uint8_t *data, unsigned int requiredLen ) {
  int len = 0;
  uint8_t *dPtr = data;
  uint8_t value = 0;
  consumeInput();
  while ( len < requiredLen ) {
    // Needs to read in 2 characters at a time
    if ( Serial.available() > 1) {
      int inByte = Serial.read();
      Serial.write(inByte);
      uint8_t val = 0;
      if ( inByte >= 'A' )
        value = inByte - 'A' + 10;
      else
        value = inByte - '0';

      value = value << 4;

      inByte = Serial.read();
      Serial.write(inByte);
      if ( inByte >= 'A' )
        value |= inByte - 'A' + 10;
      else
        value |= inByte - '0';

      *dPtr++ = value;
      len++;
    }
  }
  Serial.println();
}

/** displayMenuPrompt - Display the menu choice prompt
 */
void displayMenuPrompt() {
  Serial.print(F("Choice [1 - "));
  Serial.print(NUM_MENU_ITEM, DEC);
  Serial.print(F("] "));
}

/** displayMenu - Display the menu options and prompt
 */
void displayMenu() {
  Serial.println(F("\n\r\n\rAtmel ATECC508A Test Suite"));
  Serial.println(F(        "=========================="));
  for ( int i = 0; i < NUM_MENU_ITEM; i++ ) {
    Serial.print(i + 1, DEC);
    Serial.print(F(" - "));
    Serial.println(menu_items[i] );
    Serial.flush();
    delay(20);
  }
  displayMenuPrompt();
  delay(200);
}

/** isKeypress - Check is we've received a keypress or character over the serial link.
 * @return True for a keypress, false for no keypress
 */
boolean isKeypress() {
  if (Serial.available()) {
    int inByte = Serial.read();    // Consume character
    return true;
  }
  return false;
}


// Menu action functions - These implement the selected actions

/** menuGetInfo - The Chip Info menu action, display info about the chip
 */
void menuGetInfo() {
  Serial.println(F("\n\rChip Info"));
  uint8_t serialNum[9];

  Serial.print(F("Serial Number: "));
  uint8_t ret = ecc.getSerialNumber();
  if ( ret == 0 ) {
    const uint8_t *bufPtr = ecc.rsp.getPointer();
    int bufLen = ecc.rsp.getLength();
    // Display serial number and add to serialNum buffer
    for (int i = 0; i < bufLen; i++ ) {
      if ( i < 9)
        serialNum[i] = bufPtr[i];
      if ( bufPtr[i] < 16 ) Serial.print(F("0"));
      Serial.print(bufPtr[i], HEX);
    }
    Serial.println();
  } else {
    Serial.print(F("Failed! "));
    Serial.println(ret, HEX);
  }

  // Chip revision
  Serial.print(F("Revision: "));
  ret = ecc.getInfo(0x00, 0);
  if ( ret == 0 ) {
    displayData(ecc.rsp.getPointer(), 4);
  } else {
    Serial.print(F("Failed! "));
    Serial.println(ret, HEX);
  }

  Serial.print(F("Config Zone is" ));
  displayLockState(0);

  Serial.print(F("Data Zone is" ));
  displayLockState(1);

  // Key validity check, E for ECC keys, - for anything else
  Serial.println(F("                111111"));
  Serial.println(F("      0123456789012345"));
  Serial.print(F("Type: "));
  for ( int k = 0; k < 16; k++ ) {
    ret = ecc.getInfo(0x01, k);
    if ( ret == 0 ) {
      const uint8_t *rPtr = ecc.rsp.getPointer();
      if ( *rPtr == 0x01 )  // Has a valid public or private ECC key
        Serial.print(F("E"));
      else
        Serial.print(F("-"));
    } else {
      Serial.print(F("-"));
    }
  }
  Serial.println();

  // Display key lock state, Y for locked, - unlocked. Onlt applied to ECC keys
  Serial.print(F("Lock: "));
  uint8_t respCode = ecc.getKeySlotConfig();
  if ( respCode != 0 ) {
    Serial.print(F("Fail getKeySlotConfig "));
    displayResponse(respCode, 0);
  }
  else
  {
    uint16_t lockState = 0xFFFF;
    memcpy (&lockState, ecc.rsp.getPointer(), 2);
    slotLockState = lockState;      // Save for later slot testing
    for ( int k = 0; k < 16; k++ ) {
      Serial.print(lockState & 0x01 ? F("-") : F("Y"));
      lockState = lockState >> 1;
    }
    Serial.println();
  }

  /* This doesnt seem to indicate much
    Serial.print(F("State: "));
    ret = ecc.getInfo(0x02, 0);
    if ( ret == 0 ) {
      // TODO: Display details of bit flags
      displayData(ecc.rsp.getPointer(), 4); //ecc.rsp.getLength());
      //    ecc.rsp.dumpHex(&Serial);
      Serial.println();
    } else {
      Serial.print(F("Failed! "));
      Serial.println(ret, HEX);
    }
  */
}

/** menuPersonalize - Perform a personalize operation by writing the setup data
 *  to the chip and locking the config and data zones.
 *  Requires confirmation before this will be done.
 */
void menuPersonalize() {
  Serial.println(F("\n\rPersonalize"));
  Serial.print(F("Ready to personalise? [Y/N] "));
  consumeInput();

  boolean ended = false;

  // Loop waiting for Serial input. Check for y or Y
  if ( getConfirm() ) {
    Serial.println(F("Personalizing....."));
    // Call the personalize function
    uint8_t respCode = ecc.personalize(  config_zone, sizeof( config_zone),
                                         otp_zone, sizeof( otp_zone) );
    if ( respCode != 0 ) {
      Serial.print(F("Fail personalize "));
      displayResponse(respCode, 0);
    }
    Serial.println(F("Done"));
  }
  Serial.print(F("\n\r"));
}

/** menuGetRandom - repeatedly get random numbers and display once per second.
 * if a character is received on serial input then it stops displaying random numbers
 * and returns to menu.
 */
void menuGetRandom() {
  Serial.println(F("\n\rRandom Number"));
  Serial.println(F("Press a key to exit"));
  consumeInput();

  int count = 0;
  while ( !isKeypress() ) {
    if (0 == ecc.getRandom()) {
      ecc.rsp.dumpHex(&Serial);
    }
    else {
      Serial.println(F("Failure"));
    }
    delay(1000);
  }
  Serial.print(F("\n\r"));
}

/** menuGenPrivateKey - Generate a random private ECC key for a selected key slot.
 *  The private key remains in the chip and is not able to be read. It can be
 *  re-generated if it had not been locked. Once locked it cannot be changed.
 */
void menuGenPrivateKey() {
  Serial.println(F("\n\rGenerate Random Private ECC Key"));
  int keyNum = selectKey();
  if ( keyNum >= 0 && keyNum <= 15 ) {
    // Key entered, try to generate a random private ECC key
    Serial.print(F("Private Key "));
    Serial.println(keyNum, DEC);
    uint8_t respCode = ecc.genEccKey((uint8_t)keyNum, true);
    if ( respCode != 0 ) {
      Serial.print(F("Fail genEccKey (Private) "));
      displayResponse(respCode, keyNum);
    }
  }
}

/** menuGetPublicKey - Get the public key for a previously generated ECC private key
 *  Displays it as 128 hex characters. Is normally a 64 byte key.
 */
void menuGetPublicKey() {
  char pubkey[64];

  Serial.println(F("\n\rGet Public ECC Key"));
  int keyNum = selectKey();
  if ( keyNum >= 0 && keyNum <= 15 ) {
    // Success, get the Public key
    Serial.print(F("Public Key "));
    Serial.println(keyNum, DEC);
    uint8_t respCode = ecc.genEccKey((uint8_t)keyNum, false);
    if ( respCode != 0 ) {
      Serial.print(F("Fail genEccKey (Public) "));
      displayResponse(respCode, keyNum);
    }
    else
    {
      memcpy (pubkey, ecc.rsp.getPointer(), sizeof(pubkey));
      hexify("PubKey:", (const uint8_t *) pubkey, sizeof(pubkey));
    }
  }
}

/** menuLockKeySlot - Lock an individual ECC key slot. Once locked the private key
 *  cannot be changed. If slot is already locked then an error is shown.
 */
void menuLockKeySlot() {
  Serial.println(F("\n\rLock Key Slot"));
  int keyNum = selectKey();
  if ( keyNum >= 0 && keyNum <= 15 ) {
    Serial.print(F("Locking slot "));
    Serial.print(keyNum, DEC);
    uint8_t respCode = ecc.lockKeySlot((uint8_t)keyNum);
    if ( respCode != 0 ) {
      Serial.print(F(" "));
      displayResponse(respCode, keyNum);
      Serial.println();
    }
    else
    {
      Serial.println(F(" Locked"));
    }
  }
}

/*
void menuDumpConfig() {
  Serial.println(F("\n\rGet Key Slot Config"));
  uint8_t respCode = ecc.getKeySlotConfig();
  if ( respCode != 0 ) {
    Serial.print(F("Fail getKeySlotConfig "));
    displayResponse(respCode);
  }
  else
  {
//    memcpy (pubkey, ecc.rsp.getPointer(), sizeof(pubkey));
    hexify("Slot Config:", (const uint8_t *) ecc.rsp.getPointer(), 32);
  }

}
*/

uint8_t hash[32];
uint8_t signature[64];
uint8_t pubkey[64];

/** menuHashData - Generates a SHA256 hash of the entered data, max 62 chars.
 */
void menuHashData() {
//  uint8_t hash[32];
  uint8_t toHash[64];

  Serial.println(F("\n\rHash Data"));

  Serial.print(F("Enter Message to hash: "));
  getInputData( toHash, 62);

  // Calculate the SHA256 hash of the data.
  uint8_t ret = ecc.calculateSHA256((uint8_t*)toHash, strlen((char*)toHash));
  if ( ret != 0 )
    Serial.println(ret, HEX);
  else {
    memcpy (hash, ecc.rsp.getPointer(), sizeof(hash));
    // Display Hash for debug purposes
    hexify("Hash: ", (const uint8_t *) hash, sizeof(hash));
  }
}

/** menuSignData - Create a digital signature for some data using one of the ECC private
 *  key slots. This first generates a SHA256 hash of the data then sign.
 */
void menuSignData() {
//  uint8_t hash[32];
  uint8_t toSign[64];
//  uint8_t signature[64];
//  uint8_t pubkey[64];

  Serial.println(F("\n\rSign Data"));

  Serial.print(F("Enter Message to sign: "));
  getInputData( toSign, 62);
  
  int keyNum = selectKey();
  if ( keyNum >= 0 && keyNum <= 15 ) {
    // Calculate the SHA256 hash of the data.
    uint8_t ret = ecc.calculateSHA256((uint8_t*)toSign, strlen((char*)toSign));
    if ( ret != 0 )
      Serial.println(ret, HEX);
    else {
      memcpy (hash, ecc.rsp.getPointer(), sizeof(hash));
      if (0 != ecc.sign(keyNum, &hash[0], sizeof(hash)))
        Serial.println(F("Fail sign - Did you setup the keys?"));
      else
      {
        memcpy (signature, ecc.rsp.getPointer(), sizeof(signature));
        hexify("Signature:", (const uint8_t *) signature, sizeof(signature));
      }
    }
  }
}

/** menuVerifyData - Verify the data and its digital signature are correct and the data
 *  has not been tampered with. This first generates a SHA256 hash of the data then sign.
 */
void menuVerifyData() {
//  uint8_t signature[64];
//  uint8_t pubkey[64];
//  uint8_t hash[32];
  uint8_t toVerify[64];

  Serial.println(F("\n\rVerify Data"));

  Serial.print(F("Enter Message to verify: "));
  getInputData( toVerify, 62);

  // Enter Public key - 64 bytes, 128 hex chars
  Serial.print(F("Enter Public Key: "));
  getHexInputData( pubkey, 64 );

  // Enter Signature to verify - 64 bytes, 128 hex chars
  Serial.print(F("Enter Signature: "));
  getHexInputData( signature, 64 );

  uint8_t ret = ecc.calculateSHA256((uint8_t*)toVerify, strlen((char*)toVerify));
  if ( ret != 0 )
    Serial.println(ret, HEX);
  else {
    memcpy (hash, ecc.rsp.getPointer(), sizeof(hash));
    // Verify
    if (0 != ecc.verify(hash, sizeof(hash), pubkey, (uint8_t*)signature)) {
      Serial.println("Failed Verify");
    } else {
      Serial.println("Verify OK");
    }
  }
}

/** setup - main Arduino setup and configuration for the hardware
 */
void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
  ecc.enableDebug(&Serial);

  displayMenu();
}

/** loop - usual Arduino loop, where the main action happens
 */
void loop() {
  // Main look just waits for key presses and selects menu function
  if (Serial.available()) {
    int inByte = Serial.read();
    if ( inByte > '0' && inByte <= ('0' + NUM_MENU_ITEM )) {
      (*menu_funcs[inByte - '1'])();
      delay(500);
      //      displayMenu();
      displayMenuPrompt();

    }
    // If 0 is entered then re-display the menu
    else if (inByte == '0' ) {
      displayMenu();
    }
  }
}

