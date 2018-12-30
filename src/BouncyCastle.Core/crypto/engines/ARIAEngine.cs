﻿using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Hex = org.bouncycastle.util.encoders.Hex;

	/// <summary>
	/// RFC 5794.
	/// 
	/// ARIA is a 128-bit block cipher with 128-, 192-, and 256-bit keys.
	/// </summary>
	public class ARIAEngine : BlockCipher
	{
		private static readonly byte[][] C = new byte[][] {Hex.decode("517cc1b727220a94fe13abe8fa9a6ee0"), Hex.decode("6db14acc9e21c820ff28b1d5ef5de2b0"), Hex.decode("db92371d2126e9700324977504e8c90e")};

		private static readonly byte[] SB1_sbox = new byte[] {(byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b, unchecked((byte)0xf2), (byte)0x6b, (byte)0x6f, unchecked((byte)0xc5), (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2b, unchecked((byte)0xfe), unchecked((byte)0xd7), unchecked((byte)0xab), (byte)0x76, unchecked((byte)0xca), unchecked((byte)0x82), unchecked((byte)0xc9), (byte)0x7d, unchecked((byte)0xfa), (byte)0x59, (byte)0x47, unchecked((byte)0xf0), unchecked((byte)0xad), unchecked((byte)0xd4), unchecked((byte)0xa2), unchecked((byte)0xaf), unchecked((byte)0x9c), unchecked((byte)0xa4), (byte)0x72, unchecked((byte)0xc0), unchecked((byte)0xb7), unchecked((byte)0xfd), unchecked((byte)0x93), (byte)0x26, (byte)0x36, (byte)0x3f, unchecked((byte)0xf7), unchecked((byte)0xcc), (byte)0x34, unchecked((byte)0xa5), unchecked((byte)0xe5), unchecked((byte)0xf1), (byte)0x71, unchecked((byte)0xd8), (byte)0x31, (byte)0x15, (byte)0x04, unchecked((byte)0xc7), (byte)0x23, unchecked((byte)0xc3), (byte)0x18, unchecked((byte)0x96), (byte)0x05, unchecked((byte)0x9a), (byte)0x07, (byte)0x12, unchecked((byte)0x80), unchecked((byte)0xe2), unchecked((byte)0xeb), (byte)0x27, unchecked((byte)0xb2), (byte)0x75, (byte)0x09, unchecked((byte)0x83), (byte)0x2c, (byte)0x1a, (byte)0x1b, (byte)0x6e, (byte)0x5a, unchecked((byte)0xa0), (byte)0x52, (byte)0x3b, unchecked((byte)0xd6), unchecked((byte)0xb3), (byte)0x29, unchecked((byte)0xe3), (byte)0x2f, unchecked((byte)0x84), (byte)0x53, unchecked((byte)0xd1), (byte)0x00, unchecked((byte)0xed), (byte)0x20, unchecked((byte)0xfc), unchecked((byte)0xb1), (byte)0x5b, (byte)0x6a, unchecked((byte)0xcb), unchecked((byte)0xbe), (byte)0x39, (byte)0x4a, (byte)0x4c, (byte)0x58, unchecked((byte)0xcf), unchecked((byte)0xd0), unchecked((byte)0xef), unchecked((byte)0xaa), unchecked((byte)0xfb), (byte)0x43, (byte)0x4d, (byte)0x33, unchecked((byte)0x85), (byte)0x45, unchecked((byte)0xf9), (byte)0x02, (byte)0x7f, (byte)0x50, (byte)0x3c, unchecked((byte)0x9f), unchecked((byte)0xa8), (byte)0x51, unchecked((byte)0xa3), (byte)0x40, unchecked((byte)0x8f), unchecked((byte)0x92), unchecked((byte)0x9d), (byte)0x38, unchecked((byte)0xf5), unchecked((byte)0xbc), unchecked((byte)0xb6), unchecked((byte)0xda), (byte)0x21, (byte)0x10, unchecked((byte)0xff), unchecked((byte)0xf3), unchecked((byte)0xd2), unchecked((byte)0xcd), (byte)0x0c, (byte)0x13, unchecked((byte)0xec), (byte)0x5f, unchecked((byte)0x97), (byte)0x44, (byte)0x17, unchecked((byte)0xc4), unchecked((byte)0xa7), (byte)0x7e, (byte)0x3d, (byte)0x64, (byte)0x5d, (byte)0x19, (byte)0x73, (byte)0x60, unchecked((byte)0x81), (byte)0x4f, unchecked((byte)0xdc), (byte)0x22, (byte)0x2a, unchecked((byte)0x90), unchecked((byte)0x88), (byte)0x46, unchecked((byte)0xee), unchecked((byte)0xb8), (byte)0x14, unchecked((byte)0xde), (byte)0x5e, (byte)0x0b, unchecked((byte)0xdb), unchecked((byte)0xe0), (byte)0x32, (byte)0x3a, (byte)0x0a, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5c, unchecked((byte)0xc2), unchecked((byte)0xd3), unchecked((byte)0xac), (byte)0x62, unchecked((byte)0x91), unchecked((byte)0x95), unchecked((byte)0xe4), (byte)0x79, unchecked((byte)0xe7), unchecked((byte)0xc8), (byte)0x37, (byte)0x6d, unchecked((byte)0x8d), unchecked((byte)0xd5), (byte)0x4e, unchecked((byte)0xa9), (byte)0x6c, (byte)0x56, unchecked((byte)0xf4), unchecked((byte)0xea), (byte)0x65, (byte)0x7a, unchecked((byte)0xae), (byte)0x08, unchecked((byte)0xba), (byte)0x78, (byte)0x25, (byte)0x2e, (byte)0x1c, unchecked((byte)0xa6), unchecked((byte)0xb4), unchecked((byte)0xc6), unchecked((byte)0xe8), unchecked((byte)0xdd), (byte)0x74, (byte)0x1f, (byte)0x4b, unchecked((byte)0xbd), unchecked((byte)0x8b), unchecked((byte)0x8a), (byte)0x70, (byte)0x3e, unchecked((byte)0xb5), (byte)0x66, (byte)0x48, (byte)0x03, unchecked((byte)0xf6), (byte)0x0e, (byte)0x61, (byte)0x35, (byte)0x57, unchecked((byte)0xb9), unchecked((byte)0x86), unchecked((byte)0xc1), (byte)0x1d, unchecked((byte)0x9e), unchecked((byte)0xe1), unchecked((byte)0xf8), unchecked((byte)0x98), (byte)0x11, (byte)0x69, unchecked((byte)0xd9), unchecked((byte)0x8e), unchecked((byte)0x94), unchecked((byte)0x9b), (byte)0x1e, unchecked((byte)0x87), unchecked((byte)0xe9), unchecked((byte)0xce), (byte)0x55, (byte)0x28, unchecked((byte)0xdf), unchecked((byte)0x8c), unchecked((byte)0xa1), unchecked((byte)0x89), (byte)0x0d, unchecked((byte)0xbf), unchecked((byte)0xe6), (byte)0x42, (byte)0x68, (byte)0x41, unchecked((byte)0x99), (byte)0x2d, (byte)0x0f, unchecked((byte)0xb0), (byte)0x54, unchecked((byte)0xbb), (byte)0x16};

		private static readonly byte[] SB2_sbox = new byte[] {unchecked((byte)0xe2), (byte)0x4e, (byte)0x54, unchecked((byte)0xfc), unchecked((byte)0x94), unchecked((byte)0xc2), (byte)0x4a, unchecked((byte)0xcc), (byte)0x62, (byte)0x0d, (byte)0x6a, (byte)0x46, (byte)0x3c, (byte)0x4d, unchecked((byte)0x8b), unchecked((byte)0xd1), (byte)0x5e, unchecked((byte)0xfa), (byte)0x64, unchecked((byte)0xcb), unchecked((byte)0xb4), unchecked((byte)0x97), unchecked((byte)0xbe), (byte)0x2b, unchecked((byte)0xbc), (byte)0x77, (byte)0x2e, (byte)0x03, unchecked((byte)0xd3), (byte)0x19, (byte)0x59, unchecked((byte)0xc1), (byte)0x1d, (byte)0x06, (byte)0x41, (byte)0x6b, (byte)0x55, unchecked((byte)0xf0), unchecked((byte)0x99), (byte)0x69, unchecked((byte)0xea), unchecked((byte)0x9c), (byte)0x18, unchecked((byte)0xae), (byte)0x63, unchecked((byte)0xdf), unchecked((byte)0xe7), unchecked((byte)0xbb), (byte)0x00, (byte)0x73, (byte)0x66, unchecked((byte)0xfb), unchecked((byte)0x96), (byte)0x4c, unchecked((byte)0x85), unchecked((byte)0xe4), (byte)0x3a, (byte)0x09, (byte)0x45, unchecked((byte)0xaa), (byte)0x0f, unchecked((byte)0xee), (byte)0x10, unchecked((byte)0xeb), (byte)0x2d, (byte)0x7f, unchecked((byte)0xf4), (byte)0x29, unchecked((byte)0xac), unchecked((byte)0xcf), unchecked((byte)0xad), unchecked((byte)0x91), unchecked((byte)0x8d), (byte)0x78, unchecked((byte)0xc8), unchecked((byte)0x95), unchecked((byte)0xf9), (byte)0x2f, unchecked((byte)0xce), unchecked((byte)0xcd), (byte)0x08, (byte)0x7a, unchecked((byte)0x88), (byte)0x38, (byte)0x5c, unchecked((byte)0x83), (byte)0x2a, (byte)0x28, (byte)0x47, unchecked((byte)0xdb), unchecked((byte)0xb8), unchecked((byte)0xc7), unchecked((byte)0x93), unchecked((byte)0xa4), (byte)0x12, (byte)0x53, unchecked((byte)0xff), unchecked((byte)0x87), (byte)0x0e, (byte)0x31, (byte)0x36, (byte)0x21, (byte)0x58, (byte)0x48, (byte)0x01, unchecked((byte)0x8e), (byte)0x37, (byte)0x74, (byte)0x32, unchecked((byte)0xca), unchecked((byte)0xe9), unchecked((byte)0xb1), unchecked((byte)0xb7), unchecked((byte)0xab), (byte)0x0c, unchecked((byte)0xd7), unchecked((byte)0xc4), (byte)0x56, (byte)0x42, (byte)0x26, (byte)0x07, unchecked((byte)0x98), (byte)0x60, unchecked((byte)0xd9), unchecked((byte)0xb6), unchecked((byte)0xb9), (byte)0x11, (byte)0x40, unchecked((byte)0xec), (byte)0x20, unchecked((byte)0x8c), unchecked((byte)0xbd), unchecked((byte)0xa0), unchecked((byte)0xc9), unchecked((byte)0x84), (byte)0x04, (byte)0x49, (byte)0x23, unchecked((byte)0xf1), (byte)0x4f, (byte)0x50, (byte)0x1f, (byte)0x13, unchecked((byte)0xdc), unchecked((byte)0xd8), unchecked((byte)0xc0), unchecked((byte)0x9e), (byte)0x57, unchecked((byte)0xe3), unchecked((byte)0xc3), (byte)0x7b, (byte)0x65, (byte)0x3b, (byte)0x02, unchecked((byte)0x8f), (byte)0x3e, unchecked((byte)0xe8), (byte)0x25, unchecked((byte)0x92), unchecked((byte)0xe5), (byte)0x15, unchecked((byte)0xdd), unchecked((byte)0xfd), (byte)0x17, unchecked((byte)0xa9), unchecked((byte)0xbf), unchecked((byte)0xd4), unchecked((byte)0x9a), (byte)0x7e, unchecked((byte)0xc5), (byte)0x39, (byte)0x67, unchecked((byte)0xfe), (byte)0x76, unchecked((byte)0x9d), (byte)0x43, unchecked((byte)0xa7), unchecked((byte)0xe1), unchecked((byte)0xd0), unchecked((byte)0xf5), (byte)0x68, unchecked((byte)0xf2), (byte)0x1b, (byte)0x34, (byte)0x70, (byte)0x05, unchecked((byte)0xa3), unchecked((byte)0x8a), unchecked((byte)0xd5), (byte)0x79, unchecked((byte)0x86), unchecked((byte)0xa8), (byte)0x30, unchecked((byte)0xc6), (byte)0x51, (byte)0x4b, (byte)0x1e, unchecked((byte)0xa6), (byte)0x27, unchecked((byte)0xf6), (byte)0x35, unchecked((byte)0xd2), (byte)0x6e, (byte)0x24, (byte)0x16, unchecked((byte)0x82), (byte)0x5f, unchecked((byte)0xda), unchecked((byte)0xe6), (byte)0x75, unchecked((byte)0xa2), unchecked((byte)0xef), (byte)0x2c, unchecked((byte)0xb2), (byte)0x1c, unchecked((byte)0x9f), (byte)0x5d, (byte)0x6f, unchecked((byte)0x80), (byte)0x0a, (byte)0x72, (byte)0x44, unchecked((byte)0x9b), (byte)0x6c, unchecked((byte)0x90), (byte)0x0b, (byte)0x5b, (byte)0x33, (byte)0x7d, (byte)0x5a, (byte)0x52, unchecked((byte)0xf3), (byte)0x61, unchecked((byte)0xa1), unchecked((byte)0xf7), unchecked((byte)0xb0), unchecked((byte)0xd6), (byte)0x3f, (byte)0x7c, (byte)0x6d, unchecked((byte)0xed), (byte)0x14, unchecked((byte)0xe0), unchecked((byte)0xa5), (byte)0x3d, (byte)0x22, unchecked((byte)0xb3), unchecked((byte)0xf8), unchecked((byte)0x89), unchecked((byte)0xde), (byte)0x71, (byte)0x1a, unchecked((byte)0xaf), unchecked((byte)0xba), unchecked((byte)0xb5), unchecked((byte)0x81)};

		private static readonly byte[] SB3_sbox = new byte[] {(byte)0x52, (byte)0x09, (byte)0x6a, unchecked((byte)0xd5), (byte)0x30, (byte)0x36, unchecked((byte)0xa5), (byte)0x38, unchecked((byte)0xbf), (byte)0x40, unchecked((byte)0xa3), unchecked((byte)0x9e), unchecked((byte)0x81), unchecked((byte)0xf3), unchecked((byte)0xd7), unchecked((byte)0xfb), (byte)0x7c, unchecked((byte)0xe3), (byte)0x39, unchecked((byte)0x82), unchecked((byte)0x9b), (byte)0x2f, unchecked((byte)0xff), unchecked((byte)0x87), (byte)0x34, unchecked((byte)0x8e), (byte)0x43, (byte)0x44, unchecked((byte)0xc4), unchecked((byte)0xde), unchecked((byte)0xe9), unchecked((byte)0xcb), (byte)0x54, (byte)0x7b, unchecked((byte)0x94), (byte)0x32, unchecked((byte)0xa6), unchecked((byte)0xc2), (byte)0x23, (byte)0x3d, unchecked((byte)0xee), (byte)0x4c, unchecked((byte)0x95), (byte)0x0b, (byte)0x42, unchecked((byte)0xfa), unchecked((byte)0xc3), (byte)0x4e, (byte)0x08, (byte)0x2e, unchecked((byte)0xa1), (byte)0x66, (byte)0x28, unchecked((byte)0xd9), (byte)0x24, unchecked((byte)0xb2), (byte)0x76, (byte)0x5b, unchecked((byte)0xa2), (byte)0x49, (byte)0x6d, unchecked((byte)0x8b), unchecked((byte)0xd1), (byte)0x25, (byte)0x72, unchecked((byte)0xf8), unchecked((byte)0xf6), (byte)0x64, unchecked((byte)0x86), (byte)0x68, unchecked((byte)0x98), (byte)0x16, unchecked((byte)0xd4), unchecked((byte)0xa4), (byte)0x5c, unchecked((byte)0xcc), (byte)0x5d, (byte)0x65, unchecked((byte)0xb6), unchecked((byte)0x92), (byte)0x6c, (byte)0x70, (byte)0x48, (byte)0x50, unchecked((byte)0xfd), unchecked((byte)0xed), unchecked((byte)0xb9), unchecked((byte)0xda), (byte)0x5e, (byte)0x15, (byte)0x46, (byte)0x57, unchecked((byte)0xa7), unchecked((byte)0x8d), unchecked((byte)0x9d), unchecked((byte)0x84), unchecked((byte)0x90), unchecked((byte)0xd8), unchecked((byte)0xab), (byte)0x00, unchecked((byte)0x8c), unchecked((byte)0xbc), unchecked((byte)0xd3), (byte)0x0a, unchecked((byte)0xf7), unchecked((byte)0xe4), (byte)0x58, (byte)0x05, unchecked((byte)0xb8), unchecked((byte)0xb3), (byte)0x45, (byte)0x06, unchecked((byte)0xd0), (byte)0x2c, (byte)0x1e, unchecked((byte)0x8f), unchecked((byte)0xca), (byte)0x3f, (byte)0x0f, (byte)0x02, unchecked((byte)0xc1), unchecked((byte)0xaf), unchecked((byte)0xbd), (byte)0x03, (byte)0x01, (byte)0x13, unchecked((byte)0x8a), (byte)0x6b, (byte)0x3a, unchecked((byte)0x91), (byte)0x11, (byte)0x41, (byte)0x4f, (byte)0x67, unchecked((byte)0xdc), unchecked((byte)0xea), unchecked((byte)0x97), unchecked((byte)0xf2), unchecked((byte)0xcf), unchecked((byte)0xce), unchecked((byte)0xf0), unchecked((byte)0xb4), unchecked((byte)0xe6), (byte)0x73, unchecked((byte)0x96), unchecked((byte)0xac), (byte)0x74, (byte)0x22, unchecked((byte)0xe7), unchecked((byte)0xad), (byte)0x35, unchecked((byte)0x85), unchecked((byte)0xe2), unchecked((byte)0xf9), (byte)0x37, unchecked((byte)0xe8), (byte)0x1c, (byte)0x75, unchecked((byte)0xdf), (byte)0x6e, (byte)0x47, unchecked((byte)0xf1), (byte)0x1a, (byte)0x71, (byte)0x1d, (byte)0x29, unchecked((byte)0xc5), unchecked((byte)0x89), (byte)0x6f, unchecked((byte)0xb7), (byte)0x62, (byte)0x0e, unchecked((byte)0xaa), (byte)0x18, unchecked((byte)0xbe), (byte)0x1b, unchecked((byte)0xfc), (byte)0x56, (byte)0x3e, (byte)0x4b, unchecked((byte)0xc6), unchecked((byte)0xd2), (byte)0x79, (byte)0x20, unchecked((byte)0x9a), unchecked((byte)0xdb), unchecked((byte)0xc0), unchecked((byte)0xfe), (byte)0x78, unchecked((byte)0xcd), (byte)0x5a, unchecked((byte)0xf4), (byte)0x1f, unchecked((byte)0xdd), unchecked((byte)0xa8), (byte)0x33, unchecked((byte)0x88), (byte)0x07, unchecked((byte)0xc7), (byte)0x31, unchecked((byte)0xb1), (byte)0x12, (byte)0x10, (byte)0x59, (byte)0x27, unchecked((byte)0x80), unchecked((byte)0xec), (byte)0x5f, (byte)0x60, (byte)0x51, (byte)0x7f, unchecked((byte)0xa9), (byte)0x19, unchecked((byte)0xb5), (byte)0x4a, (byte)0x0d, (byte)0x2d, unchecked((byte)0xe5), (byte)0x7a, unchecked((byte)0x9f), unchecked((byte)0x93), unchecked((byte)0xc9), unchecked((byte)0x9c), unchecked((byte)0xef), unchecked((byte)0xa0), unchecked((byte)0xe0), (byte)0x3b, (byte)0x4d, unchecked((byte)0xae), (byte)0x2a, unchecked((byte)0xf5), unchecked((byte)0xb0), unchecked((byte)0xc8), unchecked((byte)0xeb), unchecked((byte)0xbb), (byte)0x3c, unchecked((byte)0x83), (byte)0x53, unchecked((byte)0x99), (byte)0x61, (byte)0x17, (byte)0x2b, (byte)0x04, (byte)0x7e, unchecked((byte)0xba), (byte)0x77, unchecked((byte)0xd6), (byte)0x26, unchecked((byte)0xe1), (byte)0x69, (byte)0x14, (byte)0x63, (byte)0x55, (byte)0x21, (byte)0x0c, (byte)0x7d};

		private static readonly byte[] SB4_sbox = new byte[] {(byte)0x30, (byte)0x68, unchecked((byte)0x99), (byte)0x1b, unchecked((byte)0x87), unchecked((byte)0xb9), (byte)0x21, (byte)0x78, (byte)0x50, (byte)0x39, unchecked((byte)0xdb), unchecked((byte)0xe1), (byte)0x72, (byte)0x9, (byte)0x62, (byte)0x3c, (byte)0x3e, (byte)0x7e, (byte)0x5e, unchecked((byte)0x8e), unchecked((byte)0xf1), unchecked((byte)0xa0), unchecked((byte)0xcc), unchecked((byte)0xa3), (byte)0x2a, (byte)0x1d, unchecked((byte)0xfb), unchecked((byte)0xb6), unchecked((byte)0xd6), (byte)0x20, unchecked((byte)0xc4), unchecked((byte)0x8d), unchecked((byte)0x81), (byte)0x65, unchecked((byte)0xf5), unchecked((byte)0x89), unchecked((byte)0xcb), unchecked((byte)0x9d), (byte)0x77, unchecked((byte)0xc6), (byte)0x57, (byte)0x43, (byte)0x56, (byte)0x17, unchecked((byte)0xd4), (byte)0x40, (byte)0x1a, (byte)0x4d, unchecked((byte)0xc0), (byte)0x63, (byte)0x6c, unchecked((byte)0xe3), unchecked((byte)0xb7), unchecked((byte)0xc8), (byte)0x64, (byte)0x6a, (byte)0x53, unchecked((byte)0xaa), (byte)0x38, unchecked((byte)0x98), (byte)0x0c, unchecked((byte)0xf4), unchecked((byte)0x9b), unchecked((byte)0xed), (byte)0x7f, (byte)0x22, (byte)0x76, unchecked((byte)0xaf), unchecked((byte)0xdd), (byte)0x3a, (byte)0x0b, (byte)0x58, (byte)0x67, unchecked((byte)0x88), (byte)0x06, unchecked((byte)0xc3), (byte)0x35, (byte)0x0d, (byte)0x01, unchecked((byte)0x8b), unchecked((byte)0x8c), unchecked((byte)0xc2), unchecked((byte)0xe6), (byte)0x5f, (byte)0x02, (byte)0x24, (byte)0x75, unchecked((byte)0x93), (byte)0x66, (byte)0x1e, unchecked((byte)0xe5), unchecked((byte)0xe2), (byte)0x54, unchecked((byte)0xd8), (byte)0x10, unchecked((byte)0xce), (byte)0x7a, unchecked((byte)0xe8), (byte)0x08, (byte)0x2c, (byte)0x12, unchecked((byte)0x97), (byte)0x32, unchecked((byte)0xab), unchecked((byte)0xb4), (byte)0x27, (byte)0x0a, (byte)0x23, unchecked((byte)0xdf), unchecked((byte)0xef), unchecked((byte)0xca), unchecked((byte)0xd9), unchecked((byte)0xb8), unchecked((byte)0xfa), unchecked((byte)0xdc), (byte)0x31, (byte)0x6b, unchecked((byte)0xd1), unchecked((byte)0xad), (byte)0x19, (byte)0x49, unchecked((byte)0xbd), (byte)0x51, unchecked((byte)0x96), unchecked((byte)0xee), unchecked((byte)0xe4), unchecked((byte)0xa8), (byte)0x41, unchecked((byte)0xda), unchecked((byte)0xff), unchecked((byte)0xcd), (byte)0x55, unchecked((byte)0x86), (byte)0x36, unchecked((byte)0xbe), (byte)0x61, (byte)0x52, unchecked((byte)0xf8), unchecked((byte)0xbb), (byte)0x0e, unchecked((byte)0x82), (byte)0x48, (byte)0x69, unchecked((byte)0x9a), unchecked((byte)0xe0), (byte)0x47, unchecked((byte)0x9e), (byte)0x5c, (byte)0x04, (byte)0x4b, (byte)0x34, (byte)0x15, (byte)0x79, (byte)0x26, unchecked((byte)0xa7), unchecked((byte)0xde), (byte)0x29, unchecked((byte)0xae), unchecked((byte)0x92), unchecked((byte)0xd7), unchecked((byte)0x84), unchecked((byte)0xe9), unchecked((byte)0xd2), unchecked((byte)0xba), (byte)0x5d, unchecked((byte)0xf3), unchecked((byte)0xc5), unchecked((byte)0xb0), unchecked((byte)0xbf), unchecked((byte)0xa4), (byte)0x3b, (byte)0x71, (byte)0x44, (byte)0x46, (byte)0x2b, unchecked((byte)0xfc), unchecked((byte)0xeb), (byte)0x6f, unchecked((byte)0xd5), unchecked((byte)0xf6), (byte)0x14, unchecked((byte)0xfe), (byte)0x7c, (byte)0x70, (byte)0x5a, (byte)0x7d, unchecked((byte)0xfd), (byte)0x2f, (byte)0x18, unchecked((byte)0x83), (byte)0x16, unchecked((byte)0xa5), unchecked((byte)0x91), (byte)0x1f, (byte)0x05, unchecked((byte)0x95), (byte)0x74, unchecked((byte)0xa9), unchecked((byte)0xc1), (byte)0x5b, (byte)0x4a, unchecked((byte)0x85), (byte)0x6d, (byte)0x13, (byte)0x07, (byte)0x4f, (byte)0x4e, (byte)0x45, unchecked((byte)0xb2), (byte)0x0f, unchecked((byte)0xc9), (byte)0x1c, unchecked((byte)0xa6), unchecked((byte)0xbc), unchecked((byte)0xec), (byte)0x73, unchecked((byte)0x90), (byte)0x7b, unchecked((byte)0xcf), (byte)0x59, unchecked((byte)0x8f), unchecked((byte)0xa1), unchecked((byte)0xf9), (byte)0x2d, unchecked((byte)0xf2), unchecked((byte)0xb1), (byte)0x00, unchecked((byte)0x94), (byte)0x37, unchecked((byte)0x9f), unchecked((byte)0xd0), (byte)0x2e, unchecked((byte)0x9c), (byte)0x6e, (byte)0x28, (byte)0x3f, unchecked((byte)0x80), unchecked((byte)0xf0), (byte)0x3d, unchecked((byte)0xd3), (byte)0x25, unchecked((byte)0x8a), unchecked((byte)0xb5), unchecked((byte)0xe7), (byte)0x42, unchecked((byte)0xb3), unchecked((byte)0xc7), unchecked((byte)0xea), unchecked((byte)0xf7), (byte)0x4c, (byte)0x11, (byte)0x33, (byte)0x03, unchecked((byte)0xa2), unchecked((byte)0xac), (byte)0x60};

		protected internal const int BLOCK_SIZE = 16;

		private byte[][] roundKeys;
		//private boolean forEncryption;

		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			if (!(@params is KeyParameter))
			{
				throw new IllegalArgumentException("invalid parameter passed to ARIA init - " + @params.GetType().getName());
			}

			//this.forEncryption = forEncryption;
			this.roundKeys = keySchedule(forEncryption, ((KeyParameter)@params).getKey());
		}

		public virtual string getAlgorithmName()
		{
			return "ARIA";
		}

		public virtual int getBlockSize()
		{
			return BLOCK_SIZE;
		}

		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if (roundKeys == null)
			{
				throw new IllegalStateException("ARIA engine not initialised");
			}
			if (inOff > (@in.Length - BLOCK_SIZE))
			{
				throw new DataLengthException("input buffer too short");
			}
			if (outOff > (@out.Length - BLOCK_SIZE))
			{
				throw new OutputLengthException("output buffer too short");
			}

			byte[] z = new byte[BLOCK_SIZE];
			JavaSystem.arraycopy(@in, inOff, z, 0, BLOCK_SIZE);

			int i = 0, rounds = roundKeys.Length - 3;
			while (i < rounds)
			{
				FO(z, roundKeys[i++]);
				FE(z, roundKeys[i++]);
			}

			FO(z, roundKeys[i++]);
			xor(z, roundKeys[i++]);
			SL2(z);
			xor(z, roundKeys[i]);

			JavaSystem.arraycopy(z, 0, @out, outOff, BLOCK_SIZE);

			return BLOCK_SIZE;
		}

		public virtual void reset()
		{
			// Empty
		}

		protected internal static void A(byte[] z)
		{
			byte x0 = z[0], x1 = z[1], x2 = z[2], x3 = z[3], x4 = z[4], x5 = z[5], x6 = z[6], x7 = z[7], x8 = z[8], x9 = z[9], x10 = z[10], x11 = z[11], x12 = z[12], x13 = z[13], x14 = z[14], x15 = z[15];

			z[0] = (byte)(x3 ^ x4 ^ x6 ^ x8 ^ x9 ^ x13 ^ x14);
			z[1] = (byte)(x2 ^ x5 ^ x7 ^ x8 ^ x9 ^ x12 ^ x15);
			z[2] = (byte)(x1 ^ x4 ^ x6 ^ x10 ^ x11 ^ x12 ^ x15);
			z[3] = (byte)(x0 ^ x5 ^ x7 ^ x10 ^ x11 ^ x13 ^ x14);
			z[4] = (byte)(x0 ^ x2 ^ x5 ^ x8 ^ x11 ^ x14 ^ x15);
			z[5] = (byte)(x1 ^ x3 ^ x4 ^ x9 ^ x10 ^ x14 ^ x15);
			z[6] = (byte)(x0 ^ x2 ^ x7 ^ x9 ^ x10 ^ x12 ^ x13);
			z[7] = (byte)(x1 ^ x3 ^ x6 ^ x8 ^ x11 ^ x12 ^ x13);
			z[8] = (byte)(x0 ^ x1 ^ x4 ^ x7 ^ x10 ^ x13 ^ x15);
			z[9] = (byte)(x0 ^ x1 ^ x5 ^ x6 ^ x11 ^ x12 ^ x14);
			z[10] = (byte)(x2 ^ x3 ^ x5 ^ x6 ^ x8 ^ x13 ^ x15);
			z[11] = (byte)(x2 ^ x3 ^ x4 ^ x7 ^ x9 ^ x12 ^ x14);
			z[12] = (byte)(x1 ^ x2 ^ x6 ^ x7 ^ x9 ^ x11 ^ x12);
			z[13] = (byte)(x0 ^ x3 ^ x6 ^ x7 ^ x8 ^ x10 ^ x13);
			z[14] = (byte)(x0 ^ x3 ^ x4 ^ x5 ^ x9 ^ x11 ^ x14);
			z[15] = (byte)(x1 ^ x2 ^ x4 ^ x5 ^ x8 ^ x10 ^ x15);
		}

		protected internal static void FE(byte[] D, byte[] RK)
		{
			xor(D, RK);
			SL2(D);
			A(D);
		}

		protected internal static void FO(byte[] D, byte[] RK)
		{
			xor(D, RK);
			SL1(D);
			A(D);
		}

		protected internal static byte[][] keySchedule(bool forEncryption, byte[] K)
		{
			int keyLen = K.Length;
			if (keyLen < 16 || keyLen > 32 || (keyLen & 7) != 0)
			{
				throw new IllegalArgumentException("Key length not 128/192/256 bits.");
			}

			int keyLenIdx = ((int)((uint)keyLen >> 3)) - 2;

			byte[] CK1 = C[keyLenIdx];
			byte[] CK2 = C[(keyLenIdx + 1) % 3];
			byte[] CK3 = C[(keyLenIdx + 2) % 3];

			byte[] KL = new byte[16], KR = new byte[16];
			JavaSystem.arraycopy(K, 0, KL, 0, 16);
			JavaSystem.arraycopy(K, 16, KR, 0, keyLen - 16);

			byte[] W0 = new byte[16];
			byte[] W1 = new byte[16];
			byte[] W2 = new byte[16];
			byte[] W3 = new byte[16];

			JavaSystem.arraycopy(KL, 0, W0, 0, 16);

			JavaSystem.arraycopy(W0, 0, W1, 0, 16);
			FO(W1, CK1);
			xor(W1, KR);

			JavaSystem.arraycopy(W1, 0, W2, 0, 16);
			FE(W2, CK2);
			xor(W2, W0);

			JavaSystem.arraycopy(W2, 0, W3, 0, 16);
			FO(W3, CK3);
			xor(W3, W1);

			int numRounds = 12 + (keyLenIdx * 2);
			byte[][] rks = RectangularArrays.ReturnRectangularSbyteArray(numRounds + 1, 16);

			keyScheduleRound(rks[0], W0, W1, 19);
			keyScheduleRound(rks[1], W1, W2, 19);
			keyScheduleRound(rks[2], W2, W3, 19);
			keyScheduleRound(rks[3], W3, W0, 19);

			keyScheduleRound(rks[4], W0, W1, 31);
			keyScheduleRound(rks[5], W1, W2, 31);
			keyScheduleRound(rks[6], W2, W3, 31);
			keyScheduleRound(rks[7], W3, W0, 31);

			keyScheduleRound(rks[8], W0, W1, 67);
			keyScheduleRound(rks[9], W1, W2, 67);
			keyScheduleRound(rks[10], W2, W3, 67);
			keyScheduleRound(rks[11], W3, W0, 67);

			keyScheduleRound(rks[12], W0, W1, 97);
			if (numRounds > 12)
			{
				keyScheduleRound(rks[13], W1, W2, 97);
				keyScheduleRound(rks[14], W2, W3, 97);
				if (numRounds > 14)
				{
					keyScheduleRound(rks[15], W3, W0, 97);

					keyScheduleRound(rks[16], W0, W1, 109);
				}
			}

			if (!forEncryption)
			{
				reverseKeys(rks);

				for (int i = 1; i < numRounds; ++i)
				{
					A(rks[i]);
				}
			}

			return rks;
		}

		protected internal static void keyScheduleRound(byte[] rk, byte[] w, byte[] wr, int n)
		{
			int off = (int)((uint)n >> 3), right = n & 7, left = 8 - right;

			int hi = wr[15 - off] & 0xFF;

			for (int to = 0; to < 16; ++to)
			{
				int lo = wr[(to - off) & 0xF] & 0xFF;

				int b = (hi << left) | ((int)((uint)lo >> right));
				b ^= (w[to] & 0xFF);

				rk[to] = (byte)b;

				hi = lo;
			}
		}

		protected internal static void reverseKeys(byte[][] keys)
		{
			int length = keys.Length, limit = length / 2, last = length - 1;
			for (int i = 0; i < limit; ++i)
			{
				byte[] t = keys[i];
				keys[i] = keys[last - i];
				keys[last - i] = t;
			}
		}

		protected internal static byte SB1(byte x)
		{
			return SB1_sbox[x & 0xFF];
		}

		protected internal static byte SB2(byte x)
		{
			return SB2_sbox[x & 0xFF];
		}

		protected internal static byte SB3(byte x)
		{
			return SB3_sbox[x & 0xFF];
		}

		protected internal static byte SB4(byte x)
		{
			return SB4_sbox[x & 0xFF];
		}

		protected internal static void SL1(byte[] z)
		{
			z[0] = SB1(z[0]);
			z[1] = SB2(z[1]);
			z[2] = SB3(z[2]);
			z[3] = SB4(z[3]);
			z[4] = SB1(z[4]);
			z[5] = SB2(z[5]);
			z[6] = SB3(z[6]);
			z[7] = SB4(z[7]);
			z[8] = SB1(z[8]);
			z[9] = SB2(z[9]);
			z[10] = SB3(z[10]);
			z[11] = SB4(z[11]);
			z[12] = SB1(z[12]);
			z[13] = SB2(z[13]);
			z[14] = SB3(z[14]);
			z[15] = SB4(z[15]);
		}

		protected internal static void SL2(byte[] z)
		{
			z[0] = SB3(z[0]);
			z[1] = SB4(z[1]);
			z[2] = SB1(z[2]);
			z[3] = SB2(z[3]);
			z[4] = SB3(z[4]);
			z[5] = SB4(z[5]);
			z[6] = SB1(z[6]);
			z[7] = SB2(z[7]);
			z[8] = SB3(z[8]);
			z[9] = SB4(z[9]);
			z[10] = SB1(z[10]);
			z[11] = SB2(z[11]);
			z[12] = SB3(z[12]);
			z[13] = SB4(z[13]);
			z[14] = SB1(z[14]);
			z[15] = SB2(z[15]);
		}

		protected internal static void xor(byte[] z, byte[] x)
		{
			for (int i = 0; i < 16; ++i)
			{
				z[i] ^= x[i];
			}
		}
	}

}