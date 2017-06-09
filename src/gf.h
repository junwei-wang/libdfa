/**
 * Operations in GF(256) used by AES
 */

#ifndef _GF_H_
#define _GF_H_

#include "common.h"

/**
 * Multiplication with module is x^8+x^4+x^3+x+1 (0x11b).
 */
byte gf_mul(byte, byte);

/**
 * Multiplication with 0x02.
 */
byte gf_mul2(byte);

//const byte gf_mul2_tbl[256];
static const byte gf_mul2_tbl[256] = {
  0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
  0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
  0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
  0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
  0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
  0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
  0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
  0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee, 0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
  0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
  0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
  0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
  0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
  0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
  0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
  0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
  0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5
};
static const byte gf_mul4_tbl[256] = {
  0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38, 0x3c,
  0x40, 0x44, 0x48, 0x4c, 0x50, 0x54, 0x58, 0x5c, 0x60, 0x64, 0x68, 0x6c, 0x70, 0x74, 0x78, 0x7c,
  0x80, 0x84, 0x88, 0x8c, 0x90, 0x94, 0x98, 0x9c, 0xa0, 0xa4, 0xa8, 0xac, 0xb0, 0xb4, 0xb8, 0xbc,
  0xc0, 0xc4, 0xc8, 0xcc, 0xd0, 0xd4, 0xd8, 0xdc, 0xe0, 0xe4, 0xe8, 0xec, 0xf0, 0xf4, 0xf8, 0xfc,
  0x1b, 0x1f, 0x13, 0x17, 0x0b, 0x0f, 0x03, 0x07, 0x3b, 0x3f, 0x33, 0x37, 0x2b, 0x2f, 0x23, 0x27,
  0x5b, 0x5f, 0x53, 0x57, 0x4b, 0x4f, 0x43, 0x47, 0x7b, 0x7f, 0x73, 0x77, 0x6b, 0x6f, 0x63, 0x67,
  0x9b, 0x9f, 0x93, 0x97, 0x8b, 0x8f, 0x83, 0x87, 0xbb, 0xbf, 0xb3, 0xb7, 0xab, 0xaf, 0xa3, 0xa7,
  0xdb, 0xdf, 0xd3, 0xd7, 0xcb, 0xcf, 0xc3, 0xc7, 0xfb, 0xff, 0xf3, 0xf7, 0xeb, 0xef, 0xe3, 0xe7,
  0x36, 0x32, 0x3e, 0x3a, 0x26, 0x22, 0x2e, 0x2a, 0x16, 0x12, 0x1e, 0x1a, 0x06, 0x02, 0x0e, 0x0a,
  0x76, 0x72, 0x7e, 0x7a, 0x66, 0x62, 0x6e, 0x6a, 0x56, 0x52, 0x5e, 0x5a, 0x46, 0x42, 0x4e, 0x4a,
  0xb6, 0xb2, 0xbe, 0xba, 0xa6, 0xa2, 0xae, 0xaa, 0x96, 0x92, 0x9e, 0x9a, 0x86, 0x82, 0x8e, 0x8a,
  0xf6, 0xf2, 0xfe, 0xfa, 0xe6, 0xe2, 0xee, 0xea, 0xd6, 0xd2, 0xde, 0xda, 0xc6, 0xc2, 0xce, 0xca,
  0x2d, 0x29, 0x25, 0x21, 0x3d, 0x39, 0x35, 0x31, 0x0d, 0x09, 0x05, 0x01, 0x1d, 0x19, 0x15, 0x11,
  0x6d, 0x69, 0x65, 0x61, 0x7d, 0x79, 0x75, 0x71, 0x4d, 0x49, 0x45, 0x41, 0x5d, 0x59, 0x55, 0x51,
  0xad, 0xa9, 0xa5, 0xa1, 0xbd, 0xb9, 0xb5, 0xb1, 0x8d, 0x89, 0x85, 0x81, 0x9d, 0x99, 0x95, 0x91,
  0xed, 0xe9, 0xe5, 0xe1, 0xfd, 0xf9, 0xf5, 0xf1, 0xcd, 0xc9, 0xc5, 0xc1, 0xdd, 0xd9, 0xd5, 0xd1
};
static const byte gf_mul8_tbl[256] = {
  0x00, 0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78,
  0x80, 0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0, 0xb8, 0xc0, 0xc8, 0xd0, 0xd8, 0xe0, 0xe8, 0xf0, 0xf8,
  0x1b, 0x13, 0x0b, 0x03, 0x3b, 0x33, 0x2b, 0x23, 0x5b, 0x53, 0x4b, 0x43, 0x7b, 0x73, 0x6b, 0x63,
  0x9b, 0x93, 0x8b, 0x83, 0xbb, 0xb3, 0xab, 0xa3, 0xdb, 0xd3, 0xcb, 0xc3, 0xfb, 0xf3, 0xeb, 0xe3,
  0x36, 0x3e, 0x26, 0x2e, 0x16, 0x1e, 0x06, 0x0e, 0x76, 0x7e, 0x66, 0x6e, 0x56, 0x5e, 0x46, 0x4e,
  0xb6, 0xbe, 0xa6, 0xae, 0x96, 0x9e, 0x86, 0x8e, 0xf6, 0xfe, 0xe6, 0xee, 0xd6, 0xde, 0xc6, 0xce,
  0x2d, 0x25, 0x3d, 0x35, 0x0d, 0x05, 0x1d, 0x15, 0x6d, 0x65, 0x7d, 0x75, 0x4d, 0x45, 0x5d, 0x55,
  0xad, 0xa5, 0xbd, 0xb5, 0x8d, 0x85, 0x9d, 0x95, 0xed, 0xe5, 0xfd, 0xf5, 0xcd, 0xc5, 0xdd, 0xd5,
  0x6c, 0x64, 0x7c, 0x74, 0x4c, 0x44, 0x5c, 0x54, 0x2c, 0x24, 0x3c, 0x34, 0x0c, 0x04, 0x1c, 0x14,
  0xec, 0xe4, 0xfc, 0xf4, 0xcc, 0xc4, 0xdc, 0xd4, 0xac, 0xa4, 0xbc, 0xb4, 0x8c, 0x84, 0x9c, 0x94,
  0x77, 0x7f, 0x67, 0x6f, 0x57, 0x5f, 0x47, 0x4f, 0x37, 0x3f, 0x27, 0x2f, 0x17, 0x1f, 0x07, 0x0f,
  0xf7, 0xff, 0xe7, 0xef, 0xd7, 0xdf, 0xc7, 0xcf, 0xb7, 0xbf, 0xa7, 0xaf, 0x97, 0x9f, 0x87, 0x8f,
  0x5a, 0x52, 0x4a, 0x42, 0x7a, 0x72, 0x6a, 0x62, 0x1a, 0x12, 0x0a, 0x02, 0x3a, 0x32, 0x2a, 0x22,
  0xda, 0xd2, 0xca, 0xc2, 0xfa, 0xf2, 0xea, 0xe2, 0x9a, 0x92, 0x8a, 0x82, 0xba, 0xb2, 0xaa, 0xa2,
  0x41, 0x49, 0x51, 0x59, 0x61, 0x69, 0x71, 0x79, 0x01, 0x09, 0x11, 0x19, 0x21, 0x29, 0x31, 0x39,
  0xc1, 0xc9, 0xd1, 0xd9, 0xe1, 0xe9, 0xf1, 0xf9, 0x81, 0x89, 0x91, 0x99, 0xa1, 0xa9, 0xb1, 0xb9
};


#endif//_GF_H_
