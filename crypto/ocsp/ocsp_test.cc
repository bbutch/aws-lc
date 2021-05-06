// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include <gtest/gtest.h>

#include "openssl/ocsp.h"

#include "../internal.h"

/*
 * Taken from s2n's ocsp der response test file:
 * https://github.com/aws/s2n-tls/blob/main/tests/pems/ocsp/ocsp_response.der
 */
static const uint8_t ocsp_response_der[] = {
    0x30, 0x82, 0x08, 0xb3, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x08, 0xac, 0x30,
    0x82, 0x08, 0xa8, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30,
    0x01, 0x01, 0x04, 0x82, 0x08, 0x99, 0x30, 0x82, 0x08, 0x95, 0x30, 0x81,
    0xfc, 0xa1, 0x5d, 0x30, 0x5b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
    0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
    0x55, 0x04, 0x08, 0x0c, 0x02, 0x57, 0x41, 0x31, 0x0c, 0x30, 0x0a, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x03, 0x73, 0x32, 0x6e, 0x31, 0x16, 0x30,
    0x14, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0d, 0x73, 0x32, 0x6e, 0x20,
    0x54, 0x65, 0x73, 0x74, 0x20, 0x4f, 0x43, 0x53, 0x50, 0x31, 0x19, 0x30,
    0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x10, 0x6f, 0x63, 0x73, 0x70,
    0x2e, 0x73, 0x32, 0x6e, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d,
    0x18, 0x0f, 0x32, 0x30, 0x31, 0x37, 0x31, 0x30, 0x32, 0x37, 0x30, 0x31,
    0x33, 0x30, 0x32, 0x36, 0x5a, 0x30, 0x65, 0x30, 0x63, 0x30, 0x3b, 0x30,
    0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    0xde, 0x79, 0x32, 0xb3, 0x21, 0x7e, 0x48, 0xfb, 0x4e, 0x47, 0xae, 0x0b,
    0x90, 0x07, 0xa5, 0x53, 0x76, 0xae, 0x44, 0xca, 0x04, 0x14, 0x12, 0xdf,
    0x81, 0x75, 0x71, 0xca, 0x92, 0xd3, 0xce, 0x1b, 0x2c, 0x2b, 0x77, 0x3b,
    0x9e, 0x33, 0x77, 0xf3, 0xf7, 0x6f, 0x02, 0x02, 0x77, 0x78, 0x80, 0x00,
    0x18, 0x0f, 0x32, 0x30, 0x31, 0x37, 0x31, 0x30, 0x32, 0x37, 0x30, 0x31,
    0x33, 0x30, 0x32, 0x36, 0x5a, 0xa0, 0x11, 0x18, 0x0f, 0x32, 0x31, 0x31,
    0x37, 0x31, 0x30, 0x30, 0x33, 0x30, 0x31, 0x33, 0x30, 0x32, 0x36, 0x5a,
    0xa1, 0x23, 0x30, 0x21, 0x30, 0x1f, 0x06, 0x09, 0x2b, 0x06, 0x01, 0x05,
    0x05, 0x07, 0x30, 0x01, 0x02, 0x04, 0x12, 0x04, 0x10, 0xb1, 0xa8, 0x3b,
    0x1c, 0xbf, 0xfe, 0x38, 0x6d, 0x0a, 0x71, 0xa5, 0x40, 0x24, 0x22, 0x9b,
    0x5b, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
    0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x02, 0x01, 0x00, 0x1a, 0x96, 0x80,
    0xc5, 0xe2, 0x12, 0x3f, 0x5b, 0x24, 0xaa, 0x27, 0x10, 0xf1, 0x61, 0x81,
    0x7a, 0x0a, 0x10, 0x9c, 0xa0, 0x91, 0x48, 0x13, 0xb7, 0x6b, 0x38, 0x44,
    0x40, 0x5f, 0x20, 0xff, 0x0a, 0xf0, 0xac, 0xe9, 0xbf, 0xfc, 0x33, 0x4b,
    0xf2, 0x54, 0xd8, 0x86, 0xe4, 0x59, 0x8b, 0x4b, 0xba, 0x69, 0x0c, 0xb7,
    0x75, 0x2d, 0xb1, 0x5f, 0xf5, 0xdf, 0x7d, 0x8c, 0x17, 0x46, 0xbb, 0xe5,
    0xda, 0x13, 0xba, 0x92, 0xf4, 0x16, 0x84, 0x6e, 0xce, 0xbc, 0x24, 0xde,
    0x84, 0x3d, 0x46, 0xdc, 0xa9, 0x4d, 0x46, 0x43, 0xc9, 0x9f, 0x25, 0xb0,
    0x47, 0xe5, 0x6d, 0x9d, 0x66, 0xf6, 0x36, 0x19, 0xba, 0xa2, 0xb8, 0xca,
    0xd5, 0x45, 0x3c, 0x72, 0x62, 0xe3, 0xa1, 0xff, 0xf2, 0xf3, 0x0d, 0x27,
    0xe0, 0x4f, 0x7d, 0x4e, 0x98, 0xd6, 0xf5, 0x7a, 0xb5, 0x54, 0xf7, 0x4d,
    0xeb, 0x25, 0x9e, 0xc7, 0xc8, 0xf6, 0x5a, 0x9a, 0x27, 0xe7, 0x52, 0x9b,
    0x73, 0xda, 0xad, 0xd8, 0x1b, 0x11, 0x3a, 0x49, 0xaa, 0x16, 0x56, 0xb6,
    0x73, 0x2d, 0xa6, 0xe3, 0x96, 0xf8, 0xf9, 0x13, 0x4d, 0xda, 0x49, 0x21,
    0x77, 0x6f, 0x56, 0xdf, 0x2d, 0x83, 0xcd, 0xd4, 0xd4, 0x94, 0x6b, 0xb6,
    0x39, 0xef, 0xc2, 0x47, 0x28, 0x4b, 0x1e, 0xa3, 0x60, 0xdd, 0x1b, 0x70,
    0xdb, 0x67, 0x44, 0x09, 0x3a, 0x84, 0xa5, 0xb1, 0xff, 0x1a, 0xef, 0x1c,
    0x33, 0xe0, 0x71, 0x30, 0xd6, 0xcc, 0x26, 0x4d, 0x1d, 0x06, 0x89, 0x74,
    0xf5, 0x85, 0x2c, 0x89, 0xa5, 0xc5, 0xaa, 0xc6, 0xfa, 0x9b, 0x4b, 0x5d,
    0xdb, 0x1b, 0x17, 0xd0, 0xc4, 0xfc, 0x9d, 0x3a, 0x1c, 0x71, 0x94, 0x1e,
    0x90, 0xff, 0x0e, 0xad, 0x7d, 0x8d, 0x95, 0xab, 0x01, 0xc1, 0x3b, 0x2a,
    0xba, 0xfa, 0xfd, 0xae, 0x75, 0xe1, 0x57, 0xd1, 0x4f, 0x80, 0xf3, 0xa3,
    0xfb, 0x70, 0x84, 0x36, 0x35, 0xee, 0x06, 0xbb, 0xb1, 0x66, 0x49, 0x15,
    0xb5, 0x02, 0x80, 0x34, 0x41, 0xc9, 0x61, 0x06, 0x36, 0x8e, 0xa8, 0x96,
    0x7c, 0x44, 0x32, 0x2d, 0x7b, 0x69, 0x0e, 0xe3, 0x1f, 0x83, 0x6b, 0xf2,
    0xa0, 0x45, 0xb5, 0x24, 0x5f, 0x02, 0x89, 0x16, 0x68, 0xfb, 0xbe, 0xb6,
    0xdf, 0x7e, 0xf2, 0x30, 0x0b, 0x07, 0xc2, 0x7b, 0x79, 0x96, 0x74, 0x38,
    0xf3, 0x2e, 0xbe, 0xbb, 0x8b, 0xb7, 0x4e, 0x96, 0xa4, 0xe5, 0xc5, 0x80,
    0x88, 0xca, 0x09, 0xca, 0x8e, 0x3e, 0x15, 0xb9, 0x7c, 0x23, 0xa6, 0x68,
    0xde, 0x3f, 0x65, 0xd1, 0x46, 0x0c, 0x5e, 0x42, 0xb0, 0xa0, 0x8e, 0xf5,
    0xe3, 0x27, 0x52, 0xd1, 0x0a, 0xe7, 0x53, 0xbf, 0xd8, 0x95, 0x32, 0x67,
    0xc6, 0xc9, 0x6e, 0x11, 0x46, 0x08, 0x8b, 0xa1, 0xe2, 0x85, 0x4b, 0x7c,
    0x2f, 0x91, 0xbf, 0xe4, 0x9f, 0x1e, 0x2f, 0x8f, 0x23, 0x29, 0x4a, 0x7e,
    0x5e, 0x8f, 0xdb, 0x76, 0x16, 0x88, 0xd2, 0x50, 0xb9, 0x19, 0x6c, 0xce,
    0xb0, 0xdb, 0x98, 0x0e, 0xf5, 0xf2, 0xff, 0x21, 0xab, 0x37, 0x66, 0x63,
    0x88, 0xe5, 0x33, 0x1b, 0x49, 0x95, 0x94, 0x03, 0xea, 0xf4, 0x97, 0x88,
    0xa6, 0x3d, 0x32, 0x77, 0x90, 0x0d, 0x63, 0x49, 0x06, 0x23, 0xfc, 0xdd,
    0x9d, 0x1b, 0x21, 0x99, 0x0f, 0x20, 0xed, 0x38, 0x79, 0x2f, 0x77, 0x48,
    0x20, 0x36, 0x61, 0x95, 0xde, 0xee, 0x6c, 0x68, 0x80, 0x52, 0xa4, 0xc3,
    0xa0, 0x36, 0x39, 0x9e, 0x10, 0xb1, 0x92, 0xa1, 0x47, 0x44, 0xd6, 0x5f,
    0x99, 0x20, 0xfc, 0x0b, 0xe6, 0xd0, 0x8a, 0x81, 0x5c, 0x50, 0xfd, 0x2a,
    0xc0, 0x78, 0x75, 0x10, 0x4d, 0x56, 0x1a, 0x4c, 0x89, 0x7a, 0x03, 0x23,
    0xd3, 0x12, 0x22, 0x50, 0xc0, 0x4a, 0xa3, 0xd5, 0x98, 0x5c, 0x3a, 0xe6,
    0x16, 0xde, 0xda, 0x90, 0xe2, 0xa0, 0x82, 0x05, 0x7e, 0x30, 0x82, 0x05,
    0x7a, 0x30, 0x82, 0x05, 0x76, 0x30, 0x82, 0x03, 0x5e, 0xa0, 0x03, 0x02,
    0x01, 0x02, 0x02, 0x02, 0x77, 0x79, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x28, 0x31,
    0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
    0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x02, 0x57,
    0x41, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x03,
    0x73, 0x32, 0x6e, 0x30, 0x20, 0x17, 0x0d, 0x31, 0x37, 0x30, 0x39, 0x30,
    0x35, 0x30, 0x35, 0x34, 0x33, 0x32, 0x32, 0x5a, 0x18, 0x0f, 0x32, 0x31,
    0x31, 0x37, 0x30, 0x38, 0x31, 0x32, 0x30, 0x35, 0x34, 0x33, 0x32, 0x32,
    0x5a, 0x30, 0x5b, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
    0x13, 0x02, 0x55, 0x53, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x08, 0x0c, 0x02, 0x57, 0x41, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55,
    0x04, 0x0a, 0x0c, 0x03, 0x73, 0x32, 0x6e, 0x31, 0x16, 0x30, 0x14, 0x06,
    0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0d, 0x73, 0x32, 0x6e, 0x20, 0x54, 0x65,
    0x73, 0x74, 0x20, 0x4f, 0x43, 0x53, 0x50, 0x31, 0x19, 0x30, 0x17, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0c, 0x10, 0x6f, 0x63, 0x73, 0x70, 0x2e, 0x73,
    0x32, 0x6e, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x82,
    0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00, 0x30, 0x82,
    0x02, 0x0a, 0x02, 0x82, 0x02, 0x01, 0x00, 0xaf, 0x41, 0x47, 0xed, 0x6a,
    0x7e, 0xb1, 0x31, 0x0d, 0xe6, 0x4c, 0xd8, 0x44, 0x75, 0xc5, 0x2e, 0x4f,
    0xaa, 0xaf, 0x84, 0x4e, 0xc5, 0xe0, 0xf3, 0x74, 0xd0, 0x6f, 0x02, 0x87,
    0xca, 0x51, 0x68, 0x18, 0x83, 0xdd, 0x4b, 0x7c, 0x8b, 0x31, 0xe8, 0x2d,
    0x39, 0x09, 0x88, 0x0d, 0xa5, 0xbc, 0x79, 0x67, 0x77, 0x08, 0x0f, 0x8b,
    0xc8, 0xa5, 0x8b, 0x6a, 0x7b, 0x68, 0xda, 0x05, 0x53, 0xbc, 0x35, 0x8f,
    0xbb, 0x7f, 0x01, 0x26, 0xb9, 0x98, 0xe6, 0x7b, 0x5c, 0x2a, 0xe3, 0x1b,
    0x53, 0x93, 0xb3, 0xfd, 0x2a, 0x2e, 0x38, 0xbc, 0x8f, 0xfc, 0xb1, 0x09,
    0x93, 0x95, 0xec, 0xf2, 0x96, 0xbc, 0x44, 0x3c, 0x43, 0x45, 0xa5, 0xf5,
    0xd5, 0x6c, 0x4b, 0xa9, 0xb2, 0x0c, 0xb6, 0xb8, 0x72, 0x56, 0x95, 0xad,
    0xbc, 0x67, 0x39, 0x26, 0x86, 0x61, 0x13, 0x02, 0xf3, 0xcb, 0xe1, 0xca,
    0x3b, 0x80, 0x24, 0xc9, 0x40, 0xbb, 0xbb, 0xb5, 0xd9, 0x75, 0x37, 0x2f,
    0x68, 0x6a, 0x4a, 0x31, 0x02, 0xb8, 0xa7, 0x1a, 0xb5, 0x65, 0x2c, 0x71,
    0x11, 0x46, 0xc5, 0x5a, 0xb5, 0x6f, 0x3d, 0x68, 0x20, 0xe5, 0xf2, 0x21,
    0x5b, 0xf5, 0x5d, 0x64, 0xf0, 0x36, 0x9c, 0x8f, 0x8c, 0x1f, 0xde, 0x02,
    0x1a, 0x30, 0xe2, 0x25, 0xee, 0x17, 0xc1, 0xfe, 0x5d, 0xd4, 0x96, 0xf5,
    0x33, 0xf9, 0x22, 0xff, 0xfb, 0x4a, 0xe9, 0xeb, 0x5b, 0x72, 0xb9, 0x9d,
    0x65, 0xfd, 0x99, 0xaa, 0x3a, 0xd5, 0x02, 0x65, 0xa5, 0x28, 0x5f, 0xc3,
    0x8e, 0x91, 0x13, 0xbc, 0xd4, 0xa5, 0xce, 0x2c, 0x1c, 0xb9, 0xee, 0x96,
    0x7f, 0xf5, 0xa4, 0xd4, 0xdd, 0xe0, 0x20, 0xd9, 0x24, 0x07, 0x54, 0xdf,
    0x81, 0xe5, 0x2b, 0xfa, 0x45, 0xeb, 0x3c, 0x80, 0x07, 0x5d, 0x0f, 0xfc,
    0xd6, 0xec, 0x4d, 0x18, 0x51, 0x68, 0x4f, 0x68, 0x98, 0x2f, 0x45, 0x41,
    0x93, 0x47, 0x4f, 0xdb, 0xfa, 0x39, 0xec, 0x8a, 0x41, 0xb7, 0x0e, 0xcc,
    0x6b, 0xe9, 0x64, 0xc2, 0x65, 0x60, 0x6b, 0x69, 0xb9, 0x96, 0x40, 0xee,
    0xd2, 0xb4, 0x27, 0x87, 0x5b, 0x72, 0xb7, 0xf0, 0x0f, 0x7b, 0x03, 0xb3,
    0x51, 0xbe, 0xb5, 0xae, 0x9b, 0xfd, 0xe0, 0xdc, 0x08, 0xf1, 0x44, 0xa0,
    0xaa, 0x7a, 0xd7, 0xe8, 0x66, 0xb3, 0x2a, 0x3b, 0x16, 0xc8, 0x51, 0xda,
    0x2c, 0xcd, 0x27, 0x8b, 0xf9, 0x5e, 0x88, 0x46, 0xce, 0x66, 0xd2, 0x2d,
    0xd7, 0x2b, 0x44, 0x13, 0xcd, 0xd2, 0xa7, 0xe9, 0x99, 0x3c, 0x42, 0x46,
    0xfd, 0x15, 0x00, 0x7d, 0x05, 0x04, 0x77, 0x2a, 0x89, 0xb5, 0xe3, 0x83,
    0x26, 0x1e, 0xc7, 0x91, 0x73, 0xa7, 0x02, 0x6c, 0x62, 0x59, 0x05, 0x5c,
    0x1f, 0xde, 0x47, 0x2a, 0x4c, 0xb5, 0x60, 0x86, 0xf2, 0x4d, 0x10, 0xfa,
    0x9d, 0x58, 0x06, 0x8e, 0x68, 0x94, 0x0a, 0x57, 0xb9, 0x6a, 0x51, 0x0f,
    0x9a, 0x4b, 0xb2, 0x4d, 0xf1, 0x23, 0x23, 0xd2, 0x09, 0xaa, 0x5a, 0xa4,
    0xe8, 0x97, 0xd4, 0x31, 0xa3, 0xc6, 0x97, 0x90, 0xe2, 0x8c, 0x32, 0x0f,
    0x26, 0x5f, 0xbb, 0xb4, 0x19, 0x23, 0xd4, 0xb7, 0xa9, 0x77, 0xb5, 0xca,
    0xca, 0xbe, 0xdf, 0x47, 0xc5, 0x11, 0x1c, 0x8e, 0xf8, 0xdc, 0x5a, 0x47,
    0xe8, 0x1a, 0x36, 0xfe, 0xd8, 0x1b, 0xdd, 0x2e, 0x9e, 0x21, 0x8a, 0x61,
    0xfd, 0xa7, 0x1d, 0xea, 0xcb, 0xe5, 0x98, 0xb7, 0xf0, 0xa2, 0x69, 0xe8,
    0xfc, 0xf1, 0xa3, 0x74, 0xed, 0x9b, 0x09, 0x2e, 0x1b, 0x2f, 0x71, 0x9d,
    0xde, 0x1a, 0x59, 0x0a, 0x92, 0x12, 0x07, 0xf9, 0xc1, 0x3a, 0x53, 0x53,
    0xf2, 0x94, 0x5d, 0x7e, 0x5d, 0x56, 0x89, 0x71, 0x96, 0xdb, 0x1b, 0x23,
    0x4c, 0xea, 0xe6, 0x6a, 0x9e, 0xc5, 0xcf, 0x00, 0x99, 0x6e, 0x54, 0x73,
    0x27, 0xa3, 0x0b, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x75, 0x30, 0x73,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30,
    0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x24, 0x27,
    0xf4, 0x6c, 0x82, 0x56, 0x02, 0x65, 0xea, 0xfa, 0x70, 0x9c, 0x75, 0xb9,
    0x1b, 0x6f, 0x45, 0xeb, 0x76, 0x38, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d,
    0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x12, 0xdf, 0x81, 0x75, 0x71,
    0xca, 0x92, 0xd3, 0xce, 0x1b, 0x2c, 0x2b, 0x77, 0x3b, 0x9e, 0x33, 0x77,
    0xf3, 0xf7, 0x6f, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01,
    0xff, 0x04, 0x04, 0x03, 0x02, 0x07, 0x80, 0x30, 0x16, 0x06, 0x03, 0x55,
    0x1d, 0x25, 0x01, 0x01, 0xff, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08, 0x2b,
    0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
    0x02, 0x01, 0x00, 0x8f, 0xbb, 0xc9, 0x53, 0x27, 0x88, 0x07, 0x3f, 0x27,
    0xd5, 0x04, 0x2b, 0xb6, 0xe5, 0x86, 0x35, 0x4d, 0x01, 0xbc, 0xfe, 0xdc,
    0x05, 0x69, 0x9d, 0xa0, 0xa6, 0x44, 0x80, 0x60, 0xf5, 0xc4, 0x09, 0xae,
    0xb2, 0xc8, 0xbb, 0x09, 0xc2, 0xeb, 0x0c, 0xe2, 0x16, 0xfb, 0xe4, 0xa4,
    0x63, 0x87, 0x97, 0x73, 0x92, 0xc2, 0xaa, 0x7d, 0xec, 0x4b, 0xe8, 0x93,
    0xe5, 0x9e, 0x4a, 0x8a, 0x7c, 0x28, 0xd9, 0x4e, 0xcc, 0x07, 0x63, 0xda,
    0x4d, 0xef, 0x75, 0xa8, 0x1e, 0x36, 0x55, 0x3b, 0xd9, 0xbd, 0x08, 0x3c,
    0x5c, 0x59, 0xcd, 0xc6, 0xe4, 0xb0, 0x25, 0x3f, 0x67, 0x62, 0xc0, 0x3e,
    0x03, 0x1f, 0x15, 0x73, 0x07, 0x30, 0x9f, 0x26, 0xa5, 0x3a, 0xcf, 0xb4,
    0xb3, 0x43, 0xbb, 0xaf, 0x0e, 0x65, 0x7d, 0x03, 0x76, 0x27, 0x9e, 0x47,
    0xe5, 0x81, 0x53, 0xd8, 0x78, 0x49, 0xcd, 0x64, 0xfe, 0xfa, 0x6f, 0x81,
    0x96, 0xd4, 0x79, 0xfc, 0x35, 0x74, 0x58, 0xd8, 0x7b, 0x1e, 0xcb, 0xf6,
    0xeb, 0x47, 0xda, 0xdb, 0x26, 0xa6, 0x99, 0x58, 0x3d, 0xcc, 0xa3, 0x37,
    0x41, 0xd8, 0xe4, 0xb8, 0x88, 0x4a, 0x55, 0xb5, 0x8e, 0xfc, 0x95, 0xed,
    0x78, 0xca, 0xcd, 0x29, 0x87, 0x0d, 0xdb, 0x09, 0x2f, 0x57, 0x7e, 0x41,
    0x94, 0x85, 0x8d, 0x13, 0xd7, 0xa2, 0x7b, 0xf8, 0xaa, 0x4f, 0x4f, 0xe4,
    0x0a, 0x52, 0x04, 0xc5, 0xeb, 0x65, 0x63, 0x04, 0x43, 0xee, 0xe2, 0x9a,
    0x6a, 0xf8, 0xaa, 0xb0, 0xc4, 0xc4, 0xd3, 0xf6, 0x4b, 0xbd, 0x70, 0xca,
    0x57, 0x89, 0xbd, 0x98, 0x8b, 0x9a, 0xb4, 0xb5, 0xdb, 0x94, 0x6d, 0x52,
    0xa0, 0x2a, 0x03, 0x19, 0x61, 0xee, 0xb8, 0x03, 0xe7, 0x79, 0x9d, 0xb7,
    0x52, 0xb7, 0x87, 0xc0, 0xc6, 0xc7, 0xec, 0xf8, 0x91, 0xc6, 0xc1, 0x87,
    0xf7, 0x6e, 0xb8, 0x13, 0xd5, 0x74, 0x3f, 0x48, 0xb1, 0xcd, 0x19, 0x75,
    0xcb, 0xb1, 0x34, 0x4a, 0x23, 0x07, 0xb3, 0x3e, 0xd1, 0x13, 0x74, 0x14,
    0x7a, 0xf3, 0x80, 0x15, 0x9e, 0x87, 0x2d, 0x41, 0xef, 0x77, 0x0e, 0x58,
    0x0c, 0xcf, 0xf8, 0xe3, 0x59, 0xce, 0xc3, 0xb6, 0xe4, 0x7b, 0x24, 0x47,
    0x9a, 0x1a, 0xb6, 0x8c, 0xd4, 0xa9, 0x7f, 0x5c, 0x35, 0x74, 0x78, 0xf0,
    0xa5, 0x70, 0xdc, 0x17, 0xe7, 0x4a, 0xec, 0x92, 0x54, 0x92, 0x64, 0xd8,
    0xbd, 0xf8, 0x32, 0x2a, 0x07, 0x32, 0x90, 0x44, 0xd1, 0xdc, 0x91, 0x1f,
    0x79, 0x68, 0xea, 0x88, 0x92, 0xc7, 0xb0, 0xc6, 0x1c, 0xed, 0x29, 0xc7,
    0x68, 0x7f, 0x06, 0x43, 0x33, 0x25, 0x05, 0xd1, 0xe5, 0x2a, 0xb4, 0xd9,
    0xfe, 0xc3, 0x01, 0x8d, 0x6a, 0x4e, 0x27, 0x49, 0xc4, 0x93, 0xe9, 0x0f,
    0x5a, 0xc0, 0x20, 0x55, 0xe8, 0xa2, 0xbc, 0x42, 0x53, 0x5d, 0x45, 0x33,
    0xb3, 0x08, 0xc6, 0xc6, 0x17, 0x2d, 0x5c, 0x19, 0x09, 0x13, 0xfd, 0x1f,
    0x24, 0xe9, 0x3d, 0x48, 0xff, 0x50, 0x81, 0x50, 0xcc, 0x80, 0x42, 0xf3,
    0x77, 0xb0, 0xff, 0xa9, 0xe7, 0x60, 0x70, 0x97, 0x5d, 0xb8, 0xcb, 0x78,
    0x15, 0x50, 0x3b, 0x8b, 0x0a, 0x9a, 0x9a, 0xb0, 0xbe, 0x61, 0x5f, 0x0e,
    0xfa, 0x1e, 0xd9, 0x10, 0x26, 0xb8, 0x03, 0xff, 0x50, 0x2b, 0x6c, 0x06,
    0x56, 0xaf, 0x5e, 0xa4, 0x74, 0x51, 0xac, 0x7a, 0x6f, 0x81, 0x63, 0xf2,
    0xd2, 0x74, 0xdd, 0x1f, 0x9d, 0x17, 0xc8, 0x90, 0x9e, 0xa4, 0x79, 0xc5,
    0x5f, 0xd7, 0x12, 0xb2, 0x39, 0x9c, 0x06, 0x35, 0x45, 0x9a, 0xae, 0xa4,
    0x14, 0x17, 0x67, 0xd7, 0x9f, 0xa2, 0x41, 0x86, 0x4d, 0xd4, 0x31, 0xd5,
    0x1a, 0xbe, 0x8e, 0x5c, 0xa9, 0x0d, 0xdc, 0x8a, 0x0a, 0xa9, 0x65, 0x4a,
    0xd5, 0x38, 0x22, 0xc8, 0x14, 0x5b, 0xb9, 0x5f, 0x50, 0x8b, 0x94 };


static bssl::UniquePtr<OCSP_RESPONSE> LoadOCSP_RESPONSE(bssl::Span<const uint8_t> der) {
  const uint8_t *ptr = der.data();
  return bssl::UniquePtr<OCSP_RESPONSE>(d2i_OCSP_RESPONSE(nullptr, &ptr, der.size()));
}

TEST(OCSPTest, TestBasic) {
  bssl::UniquePtr<OCSP_RESPONSE> ocsp_response;
  bssl::UniquePtr<OCSP_BASICRESP> basic_response;

  ocsp_response = LoadOCSP_RESPONSE(ocsp_response_der);
  ASSERT_TRUE(ocsp_response);

  int ocsp_status = OCSP_response_status(ocsp_response.get());
  ASSERT_EQ(OCSP_RESPONSE_STATUS_SUCCESSFUL, ocsp_status);

  basic_response = bssl::UniquePtr<OCSP_BASICRESP>(OCSP_response_get1_basic(ocsp_response.get()));
  ASSERT_TRUE(basic_response);
}