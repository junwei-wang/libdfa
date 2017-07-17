#include <stdio.h>
#include "common.h"

byte hex_char_to_byte(char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  else if (c >= 'a' && c <='f')
    return c - 'a' + 10;
  else if (c >= 'A' && c <='F')
    return c - 'A' + 10;
  return -1;
}

int hex_to_byte(const char * hex, byte * bytes, int len)
{
  LOOP(i, len) {
    bytes[i] = (hex_char_to_byte(hex[2*i]) << 4) ^ hex_char_to_byte(hex[2*i+1]);
    if (bytes[i] < 0) {
      return -1;
    }
  }
  return 0;
}

bool compare_bytes_array(const byte * a, const byte * b, int len)
{
  LOOP(i, len)
    if (a[i] != b[i])
      return false;

  return true;
}

void logging(log_level level, const char *fmt, ...)
{
  if (level < LOG_LEVEL) {
    return;
  }

  if (level == OFF) {
    printf(ANSI_COLOR_RED);
  }

  printf("[%s] ", log_level_string[level]);
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
  printf("\n");

  printf(ANSI_COLOR_RESET);
}
