#!/bin/bash

# Directory where ASIO is located
ASIO="asio-1.30.2/"
OPENSSL="-lssl -lcrypto"

# Find all directories under the include folder and add them to INCLUDE
INCLUDE=$(find include -type d -print | sed 's/^/-I/')
INCLUDE="$INCLUDE -I$ASIO"

# Find all directories under the libs folder and add them to LIB
LIB=$(find lib -type d -print | sed 's/^/-I/')

# Find all .cpp source files in the src directory
SOURCES=$(find src -name "*.cpp")

# g++ command to compile
g++ $SOURCES $INCLUDE $LIB $OPENSSL -o ./Server

chmod 744 ./Server