cryptoauth-arduino
==================

An Arduino library for Atmel's CryptoAuthentication Devices (ATSHA204x,
ATECC108x and ATECC508A).

This version is a fork of the original Cryptotronix cryptoauth-arduino library with the following changes:
1. Replace Atmel code with updated code that supports the ATECC508 chips
2. Update API to implement additional functionality to retrieve chip info, lock individual slots, add key selection to sign and verify functions.
3. Provide a comprehensive example/demo sketch covering personalization, public and private key generation, SHA256 hash generation, message signing and verification functions.

Original Readme below:


***WARNING***
-------------

This software is in pre-alpha! It's probably best that you first configure the chip on a linux based platform using the [EClet driver](https://github.com/cryptotronix/eclet) for the 108 or the [hashlet driver](https://github.com/cryptotronix/hashlet) for the 204. Once configured, you'll have an easier time of using this library.

In the example file is the basic get random function which will return a fixed test pattern if you haven't personalized your device. Once personalized (with the above linux drivers) you will get 32 bytes of random.

Feel free to create a new issue for bugs and features requests. Pull requests are welcome too :)

License
---

Atmel's code is licensed under a custom open source license. It is
included under `extras`. I share the interpretation of the license as
[these guys](https://github.com/Pinoccio/library-atmel-lwm/blob/master/README.md).
