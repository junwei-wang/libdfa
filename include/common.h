#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

// set log level
#define LOG_LEVEL OFF

// define macros
#define LOOP(i, v) for (int i=0; i<v; i++)
#define LOOP16(i) LOOP(i, 16)

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

// type definition
typedef unsigned char byte;

typedef int bool;
#define true 1
#define false 0

typedef enum {ENC, DEC} enc_mode;
typedef enum {DEBUG, INFO, WARNING, OFF} log_level;
static const char * log_level_string[] = {"DBUG", "INFO", "WARN", "NEWS"};

// convert between hex string the byte array
//  e.g. "0123456789ABCDEF" <-> {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
// return -1 if the input is invalid
int hex_to_byte(const char *, byte *, int);
int byte_to_hex(const byte *, char *, int);

// compare two bytes array with same length
int compare_bytes_array(const byte *, const byte *, int);

void logging(log_level, const char * formt, ...);

#endif//_COMMON_H_
