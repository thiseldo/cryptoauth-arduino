[![Stories in Ready](https://badge.waffle.io/cryptotronix/cryptoauth-arduino.png?label=ready&title=Ready)](https://waffle.io/cryptotronix/cryptoauth-arduino)
cryptoauth-arduino
==================

An Arduino library for Atmel's CryptoAuthentication Devices (ATSHA204x
and ATECC108x).

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
