﻿using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.engines
{
		
	/// <summary>
	/// an implementation of the AES (Rijndael), from FIPS-197.
	/// <para>
	/// For further details see: <a href="http://csrc.nist.gov/encryption/aes/">http://csrc.nist.gov/encryption/aes/</a>.
	/// 
	/// This implementation is based on optimizations from Dr. Brian Gladman's paper and C code at
	/// <a href="http://fp.gladman.plus.com/cryptography_technology/rijndael/">http://fp.gladman.plus.com/cryptography_technology/rijndael/</a>
	/// 
	/// There are three levels of tradeoff of speed vs memory
	/// Because java has no preprocessor, they are written as three separate classes from which to choose
	/// 
	/// The fastest uses 8Kbytes of static tables to precompute round calculations, 4 256 word tables for encryption
	/// and 4 for decryption.
	/// 
	/// The middle performance version uses only one 256 word table for each, for a total of 2Kbytes,
	/// adding 12 rotate operations per round to compute the values contained in the other tables from
	/// the contents of the first
	/// 
	/// The slowest version uses no static tables at all and computes the values in each round
	/// </para>
	/// <para>
	/// This file contains the fast version with 8Kbytes of static tables for round precomputation.
	/// </para> </summary>
	/// @deprecated unfortunately this class is has a few side channel issues. In an environment where encryption/decryption may be closely observed it should not be used. 
	public class AESFastEngine : BlockCipher
	{
		// The S box
		private static readonly byte[] S = new byte[] {99, 124, 119, 123, unchecked(242), 107, 111, unchecked(197), 48, 1, 103, 43, unchecked(254), unchecked(215), unchecked(171), 118, unchecked(202), unchecked(130), unchecked(201), 125, unchecked(250), 89, 71, unchecked(240), unchecked(173), unchecked(212), unchecked(162), unchecked(175), unchecked(156), unchecked(164), 114, unchecked(192), unchecked(183), unchecked(253), unchecked(147), 38, 54, 63, unchecked(247), unchecked(204), 52, unchecked(165), unchecked(229), unchecked(241), 113, unchecked(216), 49, 21, 4, unchecked(199), 35, unchecked(195), 24, unchecked(150), 5, unchecked(154), 7, 18, unchecked(128), unchecked(226), unchecked(235), 39, unchecked(178), 117, 9, unchecked(131), 44, 26, 27, 110, 90, unchecked(160), 82, 59, unchecked(214), unchecked(179), 41, unchecked(227), 47, unchecked(132), 83, unchecked(209), 0, unchecked(237), 32, unchecked(252), unchecked(177), 91, 106, unchecked(203), unchecked(190), 57, 74, 76, 88, unchecked(207), unchecked(208), unchecked(239), unchecked(170), unchecked(251), 67, 77, 51, unchecked(133), 69, unchecked(249), 2, 127, 80, 60, unchecked(159), unchecked(168), 81, unchecked(163), 64, unchecked(143), unchecked(146), unchecked(157), 56, unchecked(245), unchecked(188), unchecked(182), unchecked(218), 33, 16, unchecked(255), unchecked(243), unchecked(210), unchecked(205), 12, 19, unchecked(236), 95, unchecked(151), 68, 23, unchecked(196), unchecked(167), 126, 61, 100, 93, 25, 115, 96, unchecked(129), 79, unchecked(220), 34, 42, unchecked(144), unchecked(136), 70, unchecked(238), unchecked(184), 20, unchecked(222), 94, 11, unchecked(219), unchecked(224), 50, 58, 10, 73, 6, 36, 92, unchecked(194), unchecked(211), unchecked(172), 98, unchecked(145), unchecked(149), unchecked(228), 121, unchecked(231), unchecked(200), 55, 109, unchecked(141), unchecked(213), 78, unchecked(169), 108, 86, unchecked(244), unchecked(234), 101, 122, unchecked(174), 8, unchecked(186), 120, 37, 46, 28, unchecked(166), unchecked(180), unchecked(198), unchecked(232), unchecked(221), 116, 31, 75, unchecked(189), unchecked(139), unchecked(138), 112, 62, unchecked(181), 102, 72, 3, unchecked(246), 14, 97, 53, 87, unchecked(185), unchecked(134), unchecked(193), 29, unchecked(158), unchecked(225), unchecked(248), unchecked(152), 17, 105, unchecked(217), unchecked(142), unchecked(148), unchecked(155), 30, unchecked(135), unchecked(233), unchecked(206), 85, 40, unchecked(223), unchecked(140), unchecked(161), unchecked(137), 13, unchecked(191), unchecked(230), 66, 104, 65, unchecked(153), 45, 15, unchecked(176), 84, unchecked(187), 22};

		// The inverse S-box
		private static readonly byte[] Si = new byte[] {82, 9, 106, unchecked(213), 48, 54, unchecked(165), 56, unchecked(191), 64, unchecked(163), unchecked(158), unchecked(129), unchecked(243), unchecked(215), unchecked(251), 124, unchecked(227), 57, unchecked(130), unchecked(155), 47, unchecked(255), unchecked(135), 52, unchecked(142), 67, 68, unchecked(196), unchecked(222), unchecked(233), unchecked(203), 84, 123, unchecked(148), 50, unchecked(166), unchecked(194), 35, 61, unchecked(238), 76, unchecked(149), 11, 66, unchecked(250), unchecked(195), 78, 8, 46, unchecked(161), 102, 40, unchecked(217), 36, unchecked(178), 118, 91, unchecked(162), 73, 109, unchecked(139), unchecked(209), 37, 114, unchecked(248), unchecked(246), 100, unchecked(134), 104, unchecked(152), 22, unchecked(212), unchecked(164), 92, unchecked(204), 93, 101, unchecked(182), unchecked(146), 108, 112, 72, 80, unchecked(253), unchecked(237), unchecked(185), unchecked(218), 94, 21, 70, 87, unchecked(167), unchecked(141), unchecked(157), unchecked(132), unchecked(144), unchecked(216), unchecked(171), 0, unchecked(140), unchecked(188), unchecked(211), 10, unchecked(247), unchecked(228), 88, 5, unchecked(184), unchecked(179), 69, 6, unchecked(208), 44, 30, unchecked(143), unchecked(202), 63, 15, 2, unchecked(193), unchecked(175), unchecked(189), 3, 1, 19, unchecked(138), 107, 58, unchecked(145), 17, 65, 79, 103, unchecked(220), unchecked(234), unchecked(151), unchecked(242), unchecked(207), unchecked(206), unchecked(240), unchecked(180), unchecked(230), 115, unchecked(150), unchecked(172), 116, 34, unchecked(231), unchecked(173), 53, unchecked(133), unchecked(226), unchecked(249), 55, unchecked(232), 28, 117, unchecked(223), 110, 71, unchecked(241), 26, 113, 29, 41, unchecked(197), unchecked(137), 111, unchecked(183), 98, 14, unchecked(170), 24, unchecked(190), 27, unchecked(252), 86, 62, 75, unchecked(198), unchecked(210), 121, 32, unchecked(154), unchecked(219), unchecked(192), unchecked(254), 120, unchecked(205), 90, unchecked(244), 31, unchecked(221), unchecked(168), 51, unchecked(136), 7, unchecked(199), 49, unchecked(177), 18, 16, 89, 39, unchecked(128), unchecked(236), 95, 96, 81, 127, unchecked(169), 25, unchecked(181), 74, 13, 45, unchecked(229), 122, unchecked(159), unchecked(147), unchecked(201), unchecked(156), unchecked(239), unchecked(160), unchecked(224), 59, 77, unchecked(174), 42, unchecked(245), unchecked(176), unchecked(200), unchecked(235), unchecked(187), 60, unchecked(131), 83, unchecked(153), 97, 23, 43, 4, 126, unchecked(186), 119, unchecked(214), 38, unchecked(225), 105, 20, 99, 85, 33, 12, 125};

		// vector used in calculating key schedule (powers of x in GF(256))
		private static readonly int[] rcon = new int[] {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91};

		// precomputation tables of calculations for rounds
		private static readonly int[] T = new int[] {unchecked((int)0xa56363c6), unchecked((int)0x847c7cf8), unchecked((int)0x997777ee), unchecked((int)0x8d7b7bf6), 0x0df2f2ff, unchecked((int)0xbd6b6bd6), unchecked((int)0xb16f6fde), 0x54c5c591, 0x50303060, 0x03010102, unchecked((int)0xa96767ce), 0x7d2b2b56, 0x19fefee7, 0x62d7d7b5, unchecked((int)0xe6abab4d), unchecked((int)0x9a7676ec), 0x45caca8f, unchecked((int)0x9d82821f), 0x40c9c989, unchecked((int)0x877d7dfa), 0x15fafaef, unchecked((int)0xeb5959b2), unchecked((int)0xc947478e), 0x0bf0f0fb, unchecked((int)0xecadad41), 0x67d4d4b3, unchecked((int)0xfda2a25f), unchecked((int)0xeaafaf45), unchecked((int)0xbf9c9c23), unchecked((int)0xf7a4a453), unchecked((int)0x967272e4), 0x5bc0c09b, unchecked((int)0xc2b7b775), 0x1cfdfde1, unchecked((int)0xae93933d), 0x6a26264c, 0x5a36366c, 0x413f3f7e, 0x02f7f7f5, 0x4fcccc83, 0x5c343468, unchecked((int)0xf4a5a551), 0x34e5e5d1, 0x08f1f1f9, unchecked((int)0x937171e2), 0x73d8d8ab, 0x53313162, 0x3f15152a, 0x0c040408, 0x52c7c795, 0x65232346, 0x5ec3c39d, 0x28181830, unchecked((int)0xa1969637), 0x0f05050a, unchecked((int)0xb59a9a2f), 0x0907070e, 0x36121224, unchecked((int)0x9b80801b), 0x3de2e2df, 0x26ebebcd, 0x6927274e, unchecked((int)0xcdb2b27f), unchecked((int)0x9f7575ea), 0x1b090912, unchecked((int)0x9e83831d), 0x742c2c58, 0x2e1a1a34, 0x2d1b1b36, unchecked((int)0xb26e6edc), unchecked((int)0xee5a5ab4), unchecked((int)0xfba0a05b), unchecked((int)0xf65252a4), 0x4d3b3b76, 0x61d6d6b7, unchecked((int)0xceb3b37d), 0x7b292952, 0x3ee3e3dd, 0x712f2f5e, unchecked((int)0x97848413), unchecked((int)0xf55353a6), 0x68d1d1b9, 0x00000000, 0x2cededc1, 0x60202040, 0x1ffcfce3, unchecked((int)0xc8b1b179), unchecked((int)0xed5b5bb6), unchecked((int)0xbe6a6ad4), 0x46cbcb8d, unchecked((int)0xd9bebe67), 0x4b393972, unchecked((int)0xde4a4a94), unchecked((int)0xd44c4c98), unchecked((int)0xe85858b0), 0x4acfcf85, 0x6bd0d0bb, 0x2aefefc5, unchecked((int)0xe5aaaa4f), 0x16fbfbed, unchecked((int)0xc5434386), unchecked((int)0xd74d4d9a), 0x55333366, unchecked((int)0x94858511), unchecked((int)0xcf45458a), 0x10f9f9e9, 0x06020204, unchecked((int)0x817f7ffe), unchecked((int)0xf05050a0), 0x443c3c78, unchecked((int)0xba9f9f25), unchecked((int)0xe3a8a84b), unchecked((int)0xf35151a2), unchecked((int)0xfea3a35d), unchecked((int)0xc0404080), unchecked((int)0x8a8f8f05), unchecked((int)0xad92923f), unchecked((int)0xbc9d9d21), 0x48383870, 0x04f5f5f1, unchecked((int)0xdfbcbc63), unchecked((int)0xc1b6b677), 0x75dadaaf, 0x63212142, 0x30101020, 0x1affffe5, 0x0ef3f3fd, 0x6dd2d2bf, 0x4ccdcd81, 0x140c0c18, 0x35131326, 0x2fececc3, unchecked((int)0xe15f5fbe), unchecked((int)0xa2979735), unchecked((int)0xcc444488), 0x3917172e, 0x57c4c493, unchecked((int)0xf2a7a755), unchecked((int)0x827e7efc), 0x473d3d7a, unchecked((int)0xac6464c8), unchecked((int)0xe75d5dba), 0x2b191932, unchecked((int)0x957373e6), unchecked((int)0xa06060c0), unchecked((int)0x98818119), unchecked((int)0xd14f4f9e), 0x7fdcdca3, 0x66222244, 0x7e2a2a54, unchecked((int)0xab90903b), unchecked((int)0x8388880b), unchecked((int)0xca46468c), 0x29eeeec7, unchecked((int)0xd3b8b86b), 0x3c141428, 0x79dedea7, unchecked((int)0xe25e5ebc), 0x1d0b0b16, 0x76dbdbad, 0x3be0e0db, 0x56323264, 0x4e3a3a74, 0x1e0a0a14, unchecked((int)0xdb494992), 0x0a06060c, 0x6c242448, unchecked((int)0xe45c5cb8), 0x5dc2c29f, 0x6ed3d3bd, unchecked((int)0xefacac43), unchecked((int)0xa66262c4), unchecked((int)0xa8919139), unchecked((int)0xa4959531), 0x37e4e4d3, unchecked((int)0x8b7979f2), 0x32e7e7d5, 0x43c8c88b, 0x5937376e, unchecked((int)0xb76d6dda), unchecked((int)0x8c8d8d01), 0x64d5d5b1, unchecked((int)0xd24e4e9c), unchecked((int)0xe0a9a949), unchecked((int)0xb46c6cd8), unchecked((int)0xfa5656ac), 0x07f4f4f3, 0x25eaeacf, unchecked((int)0xaf6565ca), unchecked((int)0x8e7a7af4), unchecked((int)0xe9aeae47), 0x18080810, unchecked((int)0xd5baba6f), unchecked((int)0x887878f0), 0x6f25254a, 0x722e2e5c, 0x241c1c38, unchecked((int)0xf1a6a657), unchecked((int)0xc7b4b473), 0x51c6c697, 0x23e8e8cb, 0x7cdddda1, unchecked((int)0x9c7474e8), 0x211f1f3e, unchecked((int)0xdd4b4b96), unchecked((int)0xdcbdbd61), unchecked((int)0x868b8b0d), unchecked((int)0x858a8a0f), unchecked((int)0x907070e0), 0x423e3e7c, unchecked((int)0xc4b5b571), unchecked((int)0xaa6666cc), unchecked((int)0xd8484890), 0x05030306, 0x01f6f6f7, 0x120e0e1c, unchecked((int)0xa36161c2), 0x5f35356a, unchecked((int)0xf95757ae), unchecked((int)0xd0b9b969), unchecked((int)0x91868617), 0x58c1c199, 0x271d1d3a, unchecked((int)0xb99e9e27), 0x38e1e1d9, 0x13f8f8eb, unchecked((int)0xb398982b), 0x33111122, unchecked((int)0xbb6969d2), 0x70d9d9a9, unchecked((int)0x898e8e07), unchecked((int)0xa7949433), unchecked((int)0xb69b9b2d), 0x221e1e3c, unchecked((int)0x92878715), 0x20e9e9c9, 0x49cece87, unchecked((int)0xff5555aa), 0x78282850, 0x7adfdfa5, unchecked((int)0x8f8c8c03), unchecked((int)0xf8a1a159), unchecked((int)0x80898909), 0x170d0d1a, unchecked((int)0xdabfbf65), 0x31e6e6d7, unchecked((int)0xc6424284), unchecked((int)0xb86868d0), unchecked((int)0xc3414182), unchecked((int)0xb0999929), 0x772d2d5a, 0x110f0f1e, unchecked((int)0xcbb0b07b), unchecked((int)0xfc5454a8), unchecked((int)0xd6bbbb6d), 0x3a16162c, 0x6363c6a5, 0x7c7cf884, 0x7777ee99, 0x7b7bf68d, unchecked((int)0xf2f2ff0d), 0x6b6bd6bd, 0x6f6fdeb1, unchecked((int)0xc5c59154), 0x30306050, 0x01010203, 0x6767cea9, 0x2b2b567d, unchecked((int)0xfefee719), unchecked((int)0xd7d7b562), unchecked((int)0xabab4de6), 0x7676ec9a, unchecked((int)0xcaca8f45), unchecked((int)0x82821f9d), unchecked((int)0xc9c98940), 0x7d7dfa87, unchecked((int)0xfafaef15), 0x5959b2eb, 0x47478ec9, unchecked((int)0xf0f0fb0b), unchecked((int)0xadad41ec), unchecked((int)0xd4d4b367), unchecked((int)0xa2a25ffd), unchecked((int)0xafaf45ea), unchecked((int)0x9c9c23bf), unchecked((int)0xa4a453f7), 0x7272e496, unchecked((int)0xc0c09b5b), unchecked((int)0xb7b775c2), unchecked((int)0xfdfde11c), unchecked((int)0x93933dae), 0x26264c6a, 0x36366c5a, 0x3f3f7e41, unchecked((int)0xf7f7f502), unchecked((int)0xcccc834f), 0x3434685c, unchecked((int)0xa5a551f4), unchecked((int)0xe5e5d134), unchecked((int)0xf1f1f908), 0x7171e293, unchecked((int)0xd8d8ab73), 0x31316253, 0x15152a3f, 0x0404080c, unchecked((int)0xc7c79552), 0x23234665, unchecked((int)0xc3c39d5e), 0x18183028, unchecked((int)0x969637a1), 0x05050a0f, unchecked((int)0x9a9a2fb5), 0x07070e09, 0x12122436, unchecked((int)0x80801b9b), unchecked((int)0xe2e2df3d), unchecked((int)0xebebcd26), 0x27274e69, unchecked((int)0xb2b27fcd), 0x7575ea9f, 0x0909121b, unchecked((int)0x83831d9e), 0x2c2c5874, 0x1a1a342e, 0x1b1b362d, 0x6e6edcb2, 0x5a5ab4ee, unchecked((int)0xa0a05bfb), 0x5252a4f6, 0x3b3b764d, unchecked((int)0xd6d6b761), unchecked((int)0xb3b37dce), 0x2929527b, unchecked((int)0xe3e3dd3e), 0x2f2f5e71, unchecked((int)0x84841397), 0x5353a6f5, unchecked((int)0xd1d1b968), 0x00000000, unchecked((int)0xededc12c), 0x20204060, unchecked((int)0xfcfce31f), unchecked((int)0xb1b179c8), 0x5b5bb6ed, 0x6a6ad4be, unchecked((int)0xcbcb8d46), unchecked((int)0xbebe67d9), 0x3939724b, 0x4a4a94de, 0x4c4c98d4, 0x5858b0e8, unchecked((int)0xcfcf854a), unchecked((int)0xd0d0bb6b), unchecked((int)0xefefc52a), unchecked((int)0xaaaa4fe5), unchecked((int)0xfbfbed16), 0x434386c5, 0x4d4d9ad7, 0x33336655, unchecked((int)0x85851194), 0x45458acf, unchecked((int)0xf9f9e910), 0x02020406, 0x7f7ffe81, 0x5050a0f0, 0x3c3c7844, unchecked((int)0x9f9f25ba), unchecked((int)0xa8a84be3), 0x5151a2f3, unchecked((int)0xa3a35dfe), 0x404080c0, unchecked((int)0x8f8f058a), unchecked((int)0x92923fad), unchecked((int)0x9d9d21bc), 0x38387048, unchecked((int)0xf5f5f104), unchecked((int)0xbcbc63df), unchecked((int)0xb6b677c1), unchecked((int)0xdadaaf75), 0x21214263, 0x10102030, unchecked((int)0xffffe51a), unchecked((int)0xf3f3fd0e), unchecked((int)0xd2d2bf6d), unchecked((int)0xcdcd814c), 0x0c0c1814, 0x13132635, unchecked((int)0xececc32f), 0x5f5fbee1, unchecked((int)0x979735a2), 0x444488cc, 0x17172e39, unchecked((int)0xc4c49357), unchecked((int)0xa7a755f2), 0x7e7efc82, 0x3d3d7a47, 0x6464c8ac, 0x5d5dbae7, 0x1919322b, 0x7373e695, 0x6060c0a0, unchecked((int)0x81811998), 0x4f4f9ed1, unchecked((int)0xdcdca37f), 0x22224466, 0x2a2a547e, unchecked((int)0x90903bab), unchecked((int)0x88880b83), 0x46468cca, unchecked((int)0xeeeec729), unchecked((int)0xb8b86bd3), 0x1414283c, unchecked((int)0xdedea779), 0x5e5ebce2, 0x0b0b161d, unchecked((int)0xdbdbad76), unchecked((int)0xe0e0db3b), 0x32326456, 0x3a3a744e, 0x0a0a141e, 0x494992db, 0x06060c0a, 0x2424486c, 0x5c5cb8e4, unchecked((int)0xc2c29f5d), unchecked((int)0xd3d3bd6e), unchecked((int)0xacac43ef), 0x6262c4a6, unchecked((int)0x919139a8), unchecked((int)0x959531a4), unchecked((int)0xe4e4d337), 0x7979f28b, unchecked((int)0xe7e7d532), unchecked((int)0xc8c88b43), 0x37376e59, 0x6d6ddab7, unchecked((int)0x8d8d018c), unchecked((int)0xd5d5b164), 0x4e4e9cd2, unchecked((int)0xa9a949e0), 0x6c6cd8b4, 0x5656acfa, unchecked((int)0xf4f4f307), unchecked((int)0xeaeacf25), 0x6565caaf, 0x7a7af48e, unchecked((int)0xaeae47e9), 0x08081018, unchecked((int)0xbaba6fd5), 0x7878f088, 0x25254a6f, 0x2e2e5c72, 0x1c1c3824, unchecked((int)0xa6a657f1), unchecked((int)0xb4b473c7), unchecked((int)0xc6c69751), unchecked((int)0xe8e8cb23), unchecked((int)0xdddda17c), 0x7474e89c, 0x1f1f3e21, 0x4b4b96dd, unchecked((int)0xbdbd61dc), unchecked((int)0x8b8b0d86), unchecked((int)0x8a8a0f85), 0x7070e090, 0x3e3e7c42, unchecked((int)0xb5b571c4), 0x6666ccaa, 0x484890d8, 0x03030605, unchecked((int)0xf6f6f701), 0x0e0e1c12, 0x6161c2a3, 0x35356a5f, 0x5757aef9, unchecked((int)0xb9b969d0), unchecked((int)0x86861791), unchecked((int)0xc1c19958), 0x1d1d3a27, unchecked((int)0x9e9e27b9), unchecked((int)0xe1e1d938), unchecked((int)0xf8f8eb13), unchecked((int)0x98982bb3), 0x11112233, 0x6969d2bb, unchecked((int)0xd9d9a970), unchecked((int)0x8e8e0789), unchecked((int)0x949433a7), unchecked((int)0x9b9b2db6), 0x1e1e3c22, unchecked((int)0x87871592), unchecked((int)0xe9e9c920), unchecked((int)0xcece8749), 0x5555aaff, 0x28285078, unchecked((int)0xdfdfa57a), unchecked((int)0x8c8c038f), unchecked((int)0xa1a159f8), unchecked((int)0x89890980), 0x0d0d1a17, unchecked((int)0xbfbf65da), unchecked((int)0xe6e6d731), 0x424284c6, 0x6868d0b8, 0x414182c3, unchecked((int)0x999929b0), 0x2d2d5a77, 0x0f0f1e11, unchecked((int)0xb0b07bcb), 0x5454a8fc, unchecked((int)0xbbbb6dd6), 0x16162c3a, 0x63c6a563, 0x7cf8847c, 0x77ee9977, 0x7bf68d7b, unchecked((int)0xf2ff0df2), 0x6bd6bd6b, 0x6fdeb16f, unchecked((int)0xc59154c5), 0x30605030, 0x01020301, 0x67cea967, 0x2b567d2b, unchecked((int)0xfee719fe), unchecked((int)0xd7b562d7), unchecked((int)0xab4de6ab), 0x76ec9a76, unchecked((int)0xca8f45ca), unchecked((int)0x821f9d82), unchecked((int)0xc98940c9), 0x7dfa877d, unchecked((int)0xfaef15fa), 0x59b2eb59, 0x478ec947, unchecked((int)0xf0fb0bf0), unchecked((int)0xad41ecad), unchecked((int)0xd4b367d4), unchecked((int)0xa25ffda2), unchecked((int)0xaf45eaaf), unchecked((int)0x9c23bf9c), unchecked((int)0xa453f7a4), 0x72e49672, unchecked((int)0xc09b5bc0), unchecked((int)0xb775c2b7), unchecked((int)0xfde11cfd), unchecked((int)0x933dae93), 0x264c6a26, 0x366c5a36, 0x3f7e413f, unchecked((int)0xf7f502f7), unchecked((int)0xcc834fcc), 0x34685c34, unchecked((int)0xa551f4a5), unchecked((int)0xe5d134e5), unchecked((int)0xf1f908f1), 0x71e29371, unchecked((int)0xd8ab73d8), 0x31625331, 0x152a3f15, 0x04080c04, unchecked((int)0xc79552c7), 0x23466523, unchecked((int)0xc39d5ec3), 0x18302818, unchecked((int)0x9637a196), 0x050a0f05, unchecked((int)0x9a2fb59a), 0x070e0907, 0x12243612, unchecked((int)0x801b9b80), unchecked((int)0xe2df3de2), unchecked((int)0xebcd26eb), 0x274e6927, unchecked((int)0xb27fcdb2), 0x75ea9f75, 0x09121b09, unchecked((int)0x831d9e83), 0x2c58742c, 0x1a342e1a, 0x1b362d1b, 0x6edcb26e, 0x5ab4ee5a, unchecked((int)0xa05bfba0), 0x52a4f652, 0x3b764d3b, unchecked((int)0xd6b761d6), unchecked((int)0xb37dceb3), 0x29527b29, unchecked((int)0xe3dd3ee3), 0x2f5e712f, unchecked((int)0x84139784), 0x53a6f553, unchecked((int)0xd1b968d1), 0x00000000, unchecked((int)0xedc12ced), 0x20406020, unchecked((int)0xfce31ffc), unchecked((int)0xb179c8b1), 0x5bb6ed5b, 0x6ad4be6a, unchecked((int)0xcb8d46cb), unchecked((int)0xbe67d9be), 0x39724b39, 0x4a94de4a, 0x4c98d44c, 0x58b0e858, unchecked((int)0xcf854acf), unchecked((int)0xd0bb6bd0), unchecked((int)0xefc52aef), unchecked((int)0xaa4fe5aa), unchecked((int)0xfbed16fb), 0x4386c543, 0x4d9ad74d, 0x33665533, unchecked((int)0x85119485), 0x458acf45, unchecked((int)0xf9e910f9), 0x02040602, 0x7ffe817f, 0x50a0f050, 0x3c78443c, unchecked((int)0x9f25ba9f), unchecked((int)0xa84be3a8), 0x51a2f351, unchecked((int)0xa35dfea3), 0x4080c040, unchecked((int)0x8f058a8f), unchecked((int)0x923fad92), unchecked((int)0x9d21bc9d), 0x38704838, unchecked((int)0xf5f104f5), unchecked((int)0xbc63dfbc), unchecked((int)0xb677c1b6), unchecked((int)0xdaaf75da), 0x21426321, 0x10203010, unchecked((int)0xffe51aff), unchecked((int)0xf3fd0ef3), unchecked((int)0xd2bf6dd2), unchecked((int)0xcd814ccd), 0x0c18140c, 0x13263513, unchecked((int)0xecc32fec), 0x5fbee15f, unchecked((int)0x9735a297), 0x4488cc44, 0x172e3917, unchecked((int)0xc49357c4), unchecked((int)0xa755f2a7), 0x7efc827e, 0x3d7a473d, 0x64c8ac64, 0x5dbae75d, 0x19322b19, 0x73e69573, 0x60c0a060, unchecked((int)0x81199881), 0x4f9ed14f, unchecked((int)0xdca37fdc), 0x22446622, 0x2a547e2a, unchecked((int)0x903bab90), unchecked((int)0x880b8388), 0x468cca46, unchecked((int)0xeec729ee), unchecked((int)0xb86bd3b8), 0x14283c14, unchecked((int)0xdea779de), 0x5ebce25e, 0x0b161d0b, unchecked((int)0xdbad76db), unchecked((int)0xe0db3be0), 0x32645632, 0x3a744e3a, 0x0a141e0a, 0x4992db49, 0x060c0a06, 0x24486c24, 0x5cb8e45c, unchecked((int)0xc29f5dc2), unchecked((int)0xd3bd6ed3), unchecked((int)0xac43efac), 0x62c4a662, unchecked((int)0x9139a891), unchecked((int)0x9531a495), unchecked((int)0xe4d337e4), 0x79f28b79, unchecked((int)0xe7d532e7), unchecked((int)0xc88b43c8), 0x376e5937, 0x6ddab76d, unchecked((int)0x8d018c8d), unchecked((int)0xd5b164d5), 0x4e9cd24e, unchecked((int)0xa949e0a9), 0x6cd8b46c, 0x56acfa56, unchecked((int)0xf4f307f4), unchecked((int)0xeacf25ea), 0x65caaf65, 0x7af48e7a, unchecked((int)0xae47e9ae), 0x08101808, unchecked((int)0xba6fd5ba), 0x78f08878, 0x254a6f25, 0x2e5c722e, 0x1c38241c, unchecked((int)0xa657f1a6), unchecked((int)0xb473c7b4), unchecked((int)0xc69751c6), unchecked((int)0xe8cb23e8), unchecked((int)0xdda17cdd), 0x74e89c74, 0x1f3e211f, 0x4b96dd4b, unchecked((int)0xbd61dcbd), unchecked((int)0x8b0d868b), unchecked((int)0x8a0f858a), 0x70e09070, 0x3e7c423e, unchecked((int)0xb571c4b5), 0x66ccaa66, 0x4890d848, 0x03060503, unchecked((int)0xf6f701f6), 0x0e1c120e, 0x61c2a361, 0x356a5f35, 0x57aef957, unchecked((int)0xb969d0b9), unchecked((int)0x86179186), unchecked((int)0xc19958c1), 0x1d3a271d, unchecked((int)0x9e27b99e), unchecked((int)0xe1d938e1), unchecked((int)0xf8eb13f8), unchecked((int)0x982bb398), 0x11223311, 0x69d2bb69, unchecked((int)0xd9a970d9), unchecked((int)0x8e07898e), unchecked((int)0x9433a794), unchecked((int)0x9b2db69b), 0x1e3c221e, unchecked((int)0x87159287), unchecked((int)0xe9c920e9), unchecked((int)0xce8749ce), 0x55aaff55, 0x28507828, unchecked((int)0xdfa57adf), unchecked((int)0x8c038f8c), unchecked((int)0xa159f8a1), unchecked((int)0x89098089), 0x0d1a170d, unchecked((int)0xbf65dabf), unchecked((int)0xe6d731e6), 0x4284c642, 0x68d0b868, 0x4182c341, unchecked((int)0x9929b099), 0x2d5a772d, 0x0f1e110f, unchecked((int)0xb07bcbb0), 0x54a8fc54, unchecked((int)0xbb6dd6bb), 0x162c3a16, unchecked((int)0xc6a56363), unchecked((int)0xf8847c7c), unchecked((int)0xee997777), unchecked((int)0xf68d7b7b), unchecked((int)0xff0df2f2), unchecked((int)0xd6bd6b6b), unchecked((int)0xdeb16f6f), unchecked((int)0x9154c5c5), 0x60503030, 0x02030101, unchecked((int)0xcea96767), 0x567d2b2b, unchecked((int)0xe719fefe), unchecked((int)0xb562d7d7), 0x4de6abab, unchecked((int)0xec9a7676), unchecked((int)0x8f45caca), 0x1f9d8282, unchecked((int)0x8940c9c9), unchecked((int)0xfa877d7d), unchecked((int)0xef15fafa), unchecked((int)0xb2eb5959), unchecked((int)0x8ec94747), unchecked((int)0xfb0bf0f0), 0x41ecadad, unchecked((int)0xb367d4d4), 0x5ffda2a2, 0x45eaafaf, 0x23bf9c9c, 0x53f7a4a4, unchecked((int)0xe4967272), unchecked((int)0x9b5bc0c0), 0x75c2b7b7, unchecked((int)0xe11cfdfd), 0x3dae9393, 0x4c6a2626, 0x6c5a3636, 0x7e413f3f, unchecked((int)0xf502f7f7), unchecked((int)0x834fcccc), 0x685c3434, 0x51f4a5a5, unchecked((int)0xd134e5e5), unchecked((int)0xf908f1f1), unchecked((int)0xe2937171), unchecked((int)0xab73d8d8), 0x62533131, 0x2a3f1515, 0x080c0404, unchecked((int)0x9552c7c7), 0x46652323, unchecked((int)0x9d5ec3c3), 0x30281818, 0x37a19696, 0x0a0f0505, 0x2fb59a9a, 0x0e090707, 0x24361212, 0x1b9b8080, unchecked((int)0xdf3de2e2), unchecked((int)0xcd26ebeb), 0x4e692727, 0x7fcdb2b2, unchecked((int)0xea9f7575), 0x121b0909, 0x1d9e8383, 0x58742c2c, 0x342e1a1a, 0x362d1b1b, unchecked((int)0xdcb26e6e), unchecked((int)0xb4ee5a5a), 0x5bfba0a0, unchecked((int)0xa4f65252), 0x764d3b3b, unchecked((int)0xb761d6d6), 0x7dceb3b3, 0x527b2929, unchecked((int)0xdd3ee3e3), 0x5e712f2f, 0x13978484, unchecked((int)0xa6f55353), unchecked((int)0xb968d1d1), 0x00000000, unchecked((int)0xc12ceded), 0x40602020, unchecked((int)0xe31ffcfc), 0x79c8b1b1, unchecked((int)0xb6ed5b5b), unchecked((int)0xd4be6a6a), unchecked((int)0x8d46cbcb), 0x67d9bebe, 0x724b3939, unchecked((int)0x94de4a4a), unchecked((int)0x98d44c4c), unchecked((int)0xb0e85858), unchecked((int)0x854acfcf), unchecked((int)0xbb6bd0d0), unchecked((int)0xc52aefef), 0x4fe5aaaa, unchecked((int)0xed16fbfb), unchecked((int)0x86c54343), unchecked((int)0x9ad74d4d), 0x66553333, 0x11948585, unchecked((int)0x8acf4545), unchecked((int)0xe910f9f9), 0x04060202, unchecked((int)0xfe817f7f), unchecked((int)0xa0f05050), 0x78443c3c, 0x25ba9f9f, 0x4be3a8a8, unchecked((int)0xa2f35151), 0x5dfea3a3, unchecked((int)0x80c04040), 0x058a8f8f, 0x3fad9292, 0x21bc9d9d, 0x70483838, unchecked((int)0xf104f5f5), 0x63dfbcbc, 0x77c1b6b6, unchecked((int)0xaf75dada), 0x42632121, 0x20301010, unchecked((int)0xe51affff), unchecked((int)0xfd0ef3f3), unchecked((int)0xbf6dd2d2), unchecked((int)0x814ccdcd), 0x18140c0c, 0x26351313, unchecked((int)0xc32fecec), unchecked((int)0xbee15f5f), 0x35a29797, unchecked((int)0x88cc4444), 0x2e391717, unchecked((int)0x9357c4c4), 0x55f2a7a7, unchecked((int)0xfc827e7e), 0x7a473d3d, unchecked((int)0xc8ac6464), unchecked((int)0xbae75d5d), 0x322b1919, unchecked((int)0xe6957373), unchecked((int)0xc0a06060), 0x19988181, unchecked((int)0x9ed14f4f), unchecked((int)0xa37fdcdc), 0x44662222, 0x547e2a2a, 0x3bab9090, 0x0b838888, unchecked((int)0x8cca4646), unchecked((int)0xc729eeee), 0x6bd3b8b8, 0x283c1414, unchecked((int)0xa779dede), unchecked((int)0xbce25e5e), 0x161d0b0b, unchecked((int)0xad76dbdb), unchecked((int)0xdb3be0e0), 0x64563232, 0x744e3a3a, 0x141e0a0a, unchecked((int)0x92db4949), 0x0c0a0606, 0x486c2424, unchecked((int)0xb8e45c5c), unchecked((int)0x9f5dc2c2), unchecked((int)0xbd6ed3d3), 0x43efacac, unchecked((int)0xc4a66262), 0x39a89191, 0x31a49595, unchecked((int)0xd337e4e4), unchecked((int)0xf28b7979), unchecked((int)0xd532e7e7), unchecked((int)0x8b43c8c8), 0x6e593737, unchecked((int)0xdab76d6d), 0x018c8d8d, unchecked((int)0xb164d5d5), unchecked((int)0x9cd24e4e), 0x49e0a9a9, unchecked((int)0xd8b46c6c), unchecked((int)0xacfa5656), unchecked((int)0xf307f4f4), unchecked((int)0xcf25eaea), unchecked((int)0xcaaf6565), unchecked((int)0xf48e7a7a), 0x47e9aeae, 0x10180808, 0x6fd5baba, unchecked((int)0xf0887878), 0x4a6f2525, 0x5c722e2e, 0x38241c1c, 0x57f1a6a6, 0x73c7b4b4, unchecked((int)0x9751c6c6), unchecked((int)0xcb23e8e8), unchecked((int)0xa17cdddd), unchecked((int)0xe89c7474), 0x3e211f1f, unchecked((int)0x96dd4b4b), 0x61dcbdbd, 0x0d868b8b, 0x0f858a8a, unchecked((int)0xe0907070), 0x7c423e3e, 0x71c4b5b5, unchecked((int)0xccaa6666), unchecked((int)0x90d84848), 0x06050303, unchecked((int)0xf701f6f6), 0x1c120e0e, unchecked((int)0xc2a36161), 0x6a5f3535, unchecked((int)0xaef95757), 0x69d0b9b9, 0x17918686, unchecked((int)0x9958c1c1), 0x3a271d1d, 0x27b99e9e, unchecked((int)0xd938e1e1), unchecked((int)0xeb13f8f8), 0x2bb39898, 0x22331111, unchecked((int)0xd2bb6969), unchecked((int)0xa970d9d9), 0x07898e8e, 0x33a79494, 0x2db69b9b, 0x3c221e1e, 0x15928787, unchecked((int)0xc920e9e9), unchecked((int)0x8749cece), unchecked((int)0xaaff5555), 0x50782828, unchecked((int)0xa57adfdf), 0x038f8c8c, 0x59f8a1a1, 0x09808989, 0x1a170d0d, 0x65dabfbf, unchecked((int)0xd731e6e6), unchecked((int)0x84c64242), unchecked((int)0xd0b86868), unchecked((int)0x82c34141), 0x29b09999, 0x5a772d2d, 0x1e110f0f, 0x7bcbb0b0, unchecked((int)0xa8fc5454), 0x6dd6bbbb, 0x2c3a1616};

		private static readonly int[] Tinv = new int[] {0x50a7f451, 0x5365417e, unchecked((int)0xc3a4171a), unchecked((int)0x965e273a), unchecked((int)0xcb6bab3b), unchecked((int)0xf1459d1f), unchecked((int)0xab58faac), unchecked((int)0x9303e34b), 0x55fa3020, unchecked((int)0xf66d76ad), unchecked((int)0x9176cc88), 0x254c02f5, unchecked((int)0xfcd7e54f), unchecked((int)0xd7cb2ac5), unchecked((int)0x80443526), unchecked((int)0x8fa362b5), 0x495ab1de, 0x671bba25, unchecked((int)0x980eea45), unchecked((int)0xe1c0fe5d), 0x02752fc3, 0x12f04c81, unchecked((int)0xa397468d), unchecked((int)0xc6f9d36b), unchecked((int)0xe75f8f03), unchecked((int)0x959c9215), unchecked((int)0xeb7a6dbf), unchecked((int)0xda595295), 0x2d83bed4, unchecked((int)0xd3217458), 0x2969e049, 0x44c8c98e, 0x6a89c275, 0x78798ef4, 0x6b3e5899, unchecked((int)0xdd71b927), unchecked((int)0xb64fe1be), 0x17ad88f0, 0x66ac20c9, unchecked((int)0xb43ace7d), 0x184adf63, unchecked((int)0x82311ae5), 0x60335197, 0x457f5362, unchecked((int)0xe07764b1), unchecked((int)0x84ae6bbb), 0x1ca081fe, unchecked((int)0x942b08f9), 0x58684870, 0x19fd458f, unchecked((int)0x876cde94), unchecked((int)0xb7f87b52), 0x23d373ab, unchecked((int)0xe2024b72), 0x578f1fe3, 0x2aab5566, 0x0728ebb2, 0x03c2b52f, unchecked((int)0x9a7bc586), unchecked((int)0xa50837d3), unchecked((int)0xf2872830), unchecked((int)0xb2a5bf23), unchecked((int)0xba6a0302), 0x5c8216ed, 0x2b1ccf8a, unchecked((int)0x92b479a7), unchecked((int)0xf0f207f3), unchecked((int)0xa1e2694e), unchecked((int)0xcdf4da65), unchecked((int)0xd5be0506), 0x1f6234d1, unchecked((int)0x8afea6c4), unchecked((int)0x9d532e34), unchecked((int)0xa055f3a2), 0x32e18a05, 0x75ebf6a4, 0x39ec830b, unchecked((int)0xaaef6040), 0x069f715e, 0x51106ebd, unchecked((int)0xf98a213e), 0x3d06dd96, unchecked((int)0xae053edd), 0x46bde64d, unchecked((int)0xb58d5491), 0x055dc471, 0x6fd40604, unchecked((int)0xff155060), 0x24fb9819, unchecked((int)0x97e9bdd6), unchecked((int)0xcc434089), 0x779ed967, unchecked((int)0xbd42e8b0), unchecked((int)0x888b8907), 0x385b19e7, unchecked((int)0xdbeec879), 0x470a7ca1, unchecked((int)0xe90f427c), unchecked((int)0xc91e84f8), 0x00000000, unchecked((int)0x83868009), 0x48ed2b32, unchecked((int)0xac70111e), 0x4e725a6c, unchecked((int)0xfbff0efd), 0x5638850f, 0x1ed5ae3d, 0x27392d36, 0x64d90f0a, 0x21a65c68, unchecked((int)0xd1545b9b), 0x3a2e3624, unchecked((int)0xb1670a0c), 0x0fe75793, unchecked((int)0xd296eeb4), unchecked((int)0x9e919b1b), 0x4fc5c080, unchecked((int)0xa220dc61), 0x694b775a, 0x161a121c, 0x0aba93e2, unchecked((int)0xe52aa0c0), 0x43e0223c, 0x1d171b12, 0x0b0d090e, unchecked((int)0xadc78bf2), unchecked((int)0xb9a8b62d), unchecked((int)0xc8a91e14), unchecked((int)0x8519f157), 0x4c0775af, unchecked((int)0xbbdd99ee), unchecked((int)0xfd607fa3), unchecked((int)0x9f2601f7), unchecked((int)0xbcf5725c), unchecked((int)0xc53b6644), 0x347efb5b, 0x7629438b, unchecked((int)0xdcc623cb), 0x68fcedb6, 0x63f1e4b8, unchecked((int)0xcadc31d7), 0x10856342, 0x40229713, 0x2011c684, 0x7d244a85, unchecked((int)0xf83dbbd2), 0x1132f9ae, 0x6da129c7, 0x4b2f9e1d, unchecked((int)0xf330b2dc), unchecked((int)0xec52860d), unchecked((int)0xd0e3c177), 0x6c16b32b, unchecked((int)0x99b970a9), unchecked((int)0xfa489411), 0x2264e947, unchecked((int)0xc48cfca8), 0x1a3ff0a0, unchecked((int)0xd82c7d56), unchecked((int)0xef903322), unchecked((int)0xc74e4987), unchecked((int)0xc1d138d9), unchecked((int)0xfea2ca8c), 0x360bd498, unchecked((int)0xcf81f5a6), 0x28de7aa5, 0x268eb7da, unchecked((int)0xa4bfad3f), unchecked((int)0xe49d3a2c), 0x0d927850, unchecked((int)0x9bcc5f6a), 0x62467e54, unchecked((int)0xc2138df6), unchecked((int)0xe8b8d890), 0x5ef7392e, unchecked((int)0xf5afc382), unchecked((int)0xbe805d9f), 0x7c93d069, unchecked((int)0xa92dd56f), unchecked((int)0xb31225cf), 0x3b99acc8, unchecked((int)0xa77d1810), 0x6e639ce8, 0x7bbb3bdb, 0x097826cd, unchecked((int)0xf418596e), 0x01b79aec, unchecked((int)0xa89a4f83), 0x656e95e6, 0x7ee6ffaa, 0x08cfbc21, unchecked((int)0xe6e815ef), unchecked((int)0xd99be7ba), unchecked((int)0xce366f4a), unchecked((int)0xd4099fea), unchecked((int)0xd67cb029), unchecked((int)0xafb2a431), 0x31233f2a, 0x3094a5c6, unchecked((int)0xc066a235), 0x37bc4e74, unchecked((int)0xa6ca82fc), unchecked((int)0xb0d090e0), 0x15d8a733, 0x4a9804f1, unchecked((int)0xf7daec41), 0x0e50cd7f, 0x2ff69117, unchecked((int)0x8dd64d76), 0x4db0ef43, 0x544daacc, unchecked((int)0xdf0496e4), unchecked((int)0xe3b5d19e), 0x1b886a4c, unchecked((int)0xb81f2cc1), 0x7f516546, 0x04ea5e9d, 0x5d358c01, 0x737487fa, 0x2e410bfb, 0x5a1d67b3, 0x52d2db92, 0x335610e9, 0x1347d66d, unchecked((int)0x8c61d79a), 0x7a0ca137, unchecked((int)0x8e14f859), unchecked((int)0x893c13eb), unchecked((int)0xee27a9ce), 0x35c961b7, unchecked((int)0xede51ce1), 0x3cb1477a, 0x59dfd29c, 0x3f73f255, 0x79ce1418, unchecked((int)0xbf37c773), unchecked((int)0xeacdf753), 0x5baafd5f, 0x146f3ddf, unchecked((int)0x86db4478), unchecked((int)0x81f3afca), 0x3ec468b9, 0x2c342438, 0x5f40a3c2, 0x72c31d16, 0x0c25e2bc, unchecked((int)0x8b493c28), 0x41950dff, 0x7101a839, unchecked((int)0xdeb30c08), unchecked((int)0x9ce4b4d8), unchecked((int)0x90c15664), 0x6184cb7b, 0x70b632d5, 0x745c6c48, 0x4257b8d0, unchecked((int)0xa7f45150), 0x65417e53, unchecked((int)0xa4171ac3), 0x5e273a96, 0x6bab3bcb, 0x459d1ff1, 0x58faacab, 0x03e34b93, unchecked((int)0xfa302055), 0x6d76adf6, 0x76cc8891, 0x4c02f525, unchecked((int)0xd7e54ffc), unchecked((int)0xcb2ac5d7), 0x44352680, unchecked((int)0xa362b58f), 0x5ab1de49, 0x1bba2567, 0x0eea4598, unchecked((int)0xc0fe5de1), 0x752fc302, unchecked((int)0xf04c8112), unchecked((int)0x97468da3), unchecked((int)0xf9d36bc6), 0x5f8f03e7, unchecked((int)0x9c921595), 0x7a6dbfeb, 0x595295da, unchecked((int)0x83bed42d), 0x217458d3, 0x69e04929, unchecked((int)0xc8c98e44), unchecked((int)0x89c2756a), 0x798ef478, 0x3e58996b, 0x71b927dd, 0x4fe1beb6, unchecked((int)0xad88f017), unchecked((int)0xac20c966), 0x3ace7db4, 0x4adf6318, 0x311ae582, 0x33519760, 0x7f536245, 0x7764b1e0, unchecked((int)0xae6bbb84), unchecked((int)0xa081fe1c), 0x2b08f994, 0x68487058, unchecked((int)0xfd458f19), 0x6cde9487, unchecked((int)0xf87b52b7), unchecked((int)0xd373ab23), 0x024b72e2, unchecked((int)0x8f1fe357), unchecked((int)0xab55662a), 0x28ebb207, unchecked((int)0xc2b52f03), 0x7bc5869a, 0x0837d3a5, unchecked((int)0x872830f2), unchecked((int)0xa5bf23b2), 0x6a0302ba, unchecked((int)0x8216ed5c), 0x1ccf8a2b, unchecked((int)0xb479a792), unchecked((int)0xf207f3f0), unchecked((int)0xe2694ea1), unchecked((int)0xf4da65cd), unchecked((int)0xbe0506d5), 0x6234d11f, unchecked((int)0xfea6c48a), 0x532e349d, 0x55f3a2a0, unchecked((int)0xe18a0532), unchecked((int)0xebf6a475), unchecked((int)0xec830b39), unchecked((int)0xef6040aa), unchecked((int)0x9f715e06), 0x106ebd51, unchecked((int)0x8a213ef9), 0x06dd963d, 0x053eddae, unchecked((int)0xbde64d46), unchecked((int)0x8d5491b5), 0x5dc47105, unchecked((int)0xd406046f), 0x155060ff, unchecked((int)0xfb981924), unchecked((int)0xe9bdd697), 0x434089cc, unchecked((int)0x9ed96777), 0x42e8b0bd, unchecked((int)0x8b890788), 0x5b19e738, unchecked((int)0xeec879db), 0x0a7ca147, 0x0f427ce9, 0x1e84f8c9, 0x00000000, unchecked((int)0x86800983), unchecked((int)0xed2b3248), 0x70111eac, 0x725a6c4e, unchecked((int)0xff0efdfb), 0x38850f56, unchecked((int)0xd5ae3d1e), 0x392d3627, unchecked((int)0xd90f0a64), unchecked((int)0xa65c6821), 0x545b9bd1, 0x2e36243a, 0x670a0cb1, unchecked((int)0xe757930f), unchecked((int)0x96eeb4d2), unchecked((int)0x919b1b9e), unchecked((int)0xc5c0804f), 0x20dc61a2, 0x4b775a69, 0x1a121c16, unchecked((int)0xba93e20a), 0x2aa0c0e5, unchecked((int)0xe0223c43), 0x171b121d, 0x0d090e0b, unchecked((int)0xc78bf2ad), unchecked((int)0xa8b62db9), unchecked((int)0xa91e14c8), 0x19f15785, 0x0775af4c, unchecked((int)0xdd99eebb), 0x607fa3fd, 0x2601f79f, unchecked((int)0xf5725cbc), 0x3b6644c5, 0x7efb5b34, 0x29438b76, unchecked((int)0xc623cbdc), unchecked((int)0xfcedb668), unchecked((int)0xf1e4b863), unchecked((int)0xdc31d7ca), unchecked((int)0x85634210), 0x22971340, 0x11c68420, 0x244a857d, 0x3dbbd2f8, 0x32f9ae11, unchecked((int)0xa129c76d), 0x2f9e1d4b, 0x30b2dcf3, 0x52860dec, unchecked((int)0xe3c177d0), 0x16b32b6c, unchecked((int)0xb970a999), 0x489411fa, 0x64e94722, unchecked((int)0x8cfca8c4), 0x3ff0a01a, 0x2c7d56d8, unchecked((int)0x903322ef), 0x4e4987c7, unchecked((int)0xd138d9c1), unchecked((int)0xa2ca8cfe), 0x0bd49836, unchecked((int)0x81f5a6cf), unchecked((int)0xde7aa528), unchecked((int)0x8eb7da26), unchecked((int)0xbfad3fa4), unchecked((int)0x9d3a2ce4), unchecked((int)0x9278500d), unchecked((int)0xcc5f6a9b), 0x467e5462, 0x138df6c2, unchecked((int)0xb8d890e8), unchecked((int)0xf7392e5e), unchecked((int)0xafc382f5), unchecked((int)0x805d9fbe), unchecked((int)0x93d0697c), 0x2dd56fa9, 0x1225cfb3, unchecked((int)0x99acc83b), 0x7d1810a7, 0x639ce86e, unchecked((int)0xbb3bdb7b), 0x7826cd09, 0x18596ef4, unchecked((int)0xb79aec01), unchecked((int)0x9a4f83a8), 0x6e95e665, unchecked((int)0xe6ffaa7e), unchecked((int)0xcfbc2108), unchecked((int)0xe815efe6), unchecked((int)0x9be7bad9), 0x366f4ace, 0x099fead4, 0x7cb029d6, unchecked((int)0xb2a431af), 0x233f2a31, unchecked((int)0x94a5c630), 0x66a235c0, unchecked((int)0xbc4e7437), unchecked((int)0xca82fca6), unchecked((int)0xd090e0b0), unchecked((int)0xd8a73315), unchecked((int)0x9804f14a), unchecked((int)0xdaec41f7), 0x50cd7f0e, unchecked((int)0xf691172f), unchecked((int)0xd64d768d), unchecked((int)0xb0ef434d), 0x4daacc54, 0x0496e4df, unchecked((int)0xb5d19ee3), unchecked((int)0x886a4c1b), 0x1f2cc1b8, 0x5165467f, unchecked((int)0xea5e9d04), 0x358c015d, 0x7487fa73, 0x410bfb2e, 0x1d67b35a, unchecked((int)0xd2db9252), 0x5610e933, 0x47d66d13, 0x61d79a8c, 0x0ca1377a, 0x14f8598e, 0x3c13eb89, 0x27a9ceee, unchecked((int)0xc961b735), unchecked((int)0xe51ce1ed), unchecked((int)0xb1477a3c), unchecked((int)0xdfd29c59), 0x73f2553f, unchecked((int)0xce141879), 0x37c773bf, unchecked((int)0xcdf753ea), unchecked((int)0xaafd5f5b), 0x6f3ddf14, unchecked((int)0xdb447886), unchecked((int)0xf3afca81), unchecked((int)0xc468b93e), 0x3424382c, 0x40a3c25f, unchecked((int)0xc31d1672), 0x25e2bc0c, 0x493c288b, unchecked((int)0x950dff41), 0x01a83971, unchecked((int)0xb30c08de), unchecked((int)0xe4b4d89c), unchecked((int)0xc1566490), unchecked((int)0x84cb7b61), unchecked((int)0xb632d570), 0x5c6c4874, 0x57b8d042, unchecked((int)0xf45150a7), 0x417e5365, 0x171ac3a4, 0x273a965e, unchecked((int)0xab3bcb6b), unchecked((int)0x9d1ff145), unchecked((int)0xfaacab58), unchecked((int)0xe34b9303), 0x302055fa, 0x76adf66d, unchecked((int)0xcc889176), 0x02f5254c, unchecked((int)0xe54ffcd7), 0x2ac5d7cb, 0x35268044, 0x62b58fa3, unchecked((int)0xb1de495a), unchecked((int)0xba25671b), unchecked((int)0xea45980e), unchecked((int)0xfe5de1c0), 0x2fc30275, 0x4c8112f0, 0x468da397, unchecked((int)0xd36bc6f9), unchecked((int)0x8f03e75f), unchecked((int)0x9215959c), 0x6dbfeb7a, 0x5295da59, unchecked((int)0xbed42d83), 0x7458d321, unchecked((int)0xe0492969), unchecked((int)0xc98e44c8), unchecked((int)0xc2756a89), unchecked((int)0x8ef47879), 0x58996b3e, unchecked((int)0xb927dd71), unchecked((int)0xe1beb64f), unchecked((int)0x88f017ad), 0x20c966ac, unchecked((int)0xce7db43a), unchecked((int)0xdf63184a), 0x1ae58231, 0x51976033, 0x5362457f, 0x64b1e077, 0x6bbb84ae, unchecked((int)0x81fe1ca0), 0x08f9942b, 0x48705868, 0x458f19fd, unchecked((int)0xde94876c), 0x7b52b7f8, 0x73ab23d3, 0x4b72e202, 0x1fe3578f, 0x55662aab, unchecked((int)0xebb20728), unchecked((int)0xb52f03c2), unchecked((int)0xc5869a7b), 0x37d3a508, 0x2830f287, unchecked((int)0xbf23b2a5), 0x0302ba6a, 0x16ed5c82, unchecked((int)0xcf8a2b1c), 0x79a792b4, 0x07f3f0f2, 0x694ea1e2, unchecked((int)0xda65cdf4), 0x0506d5be, 0x34d11f62, unchecked((int)0xa6c48afe), 0x2e349d53, unchecked((int)0xf3a2a055), unchecked((int)0x8a0532e1), unchecked((int)0xf6a475eb), unchecked((int)0x830b39ec), 0x6040aaef, 0x715e069f, 0x6ebd5110, 0x213ef98a, unchecked((int)0xdd963d06), 0x3eddae05, unchecked((int)0xe64d46bd), 0x5491b58d, unchecked((int)0xc471055d), 0x06046fd4, 0x5060ff15, unchecked((int)0x981924fb), unchecked((int)0xbdd697e9), 0x4089cc43, unchecked((int)0xd967779e), unchecked((int)0xe8b0bd42), unchecked((int)0x8907888b), 0x19e7385b, unchecked((int)0xc879dbee), 0x7ca1470a, 0x427ce90f, unchecked((int)0x84f8c91e), 0x00000000, unchecked((int)0x80098386), 0x2b3248ed, 0x111eac70, 0x5a6c4e72, 0x0efdfbff, unchecked((int)0x850f5638), unchecked((int)0xae3d1ed5), 0x2d362739, 0x0f0a64d9, 0x5c6821a6, 0x5b9bd154, 0x36243a2e, 0x0a0cb167, 0x57930fe7, unchecked((int)0xeeb4d296), unchecked((int)0x9b1b9e91), unchecked((int)0xc0804fc5), unchecked((int)0xdc61a220), 0x775a694b, 0x121c161a, unchecked((int)0x93e20aba), unchecked((int)0xa0c0e52a), 0x223c43e0, 0x1b121d17, 0x090e0b0d, unchecked((int)0x8bf2adc7), unchecked((int)0xb62db9a8), 0x1e14c8a9, unchecked((int)0xf1578519), 0x75af4c07, unchecked((int)0x99eebbdd), 0x7fa3fd60, 0x01f79f26, 0x725cbcf5, 0x6644c53b, unchecked((int)0xfb5b347e), 0x438b7629, 0x23cbdcc6, unchecked((int)0xedb668fc), unchecked((int)0xe4b863f1), 0x31d7cadc, 0x63421085, unchecked((int)0x97134022), unchecked((int)0xc6842011), 0x4a857d24, unchecked((int)0xbbd2f83d), unchecked((int)0xf9ae1132), 0x29c76da1, unchecked((int)0x9e1d4b2f), unchecked((int)0xb2dcf330), unchecked((int)0x860dec52), unchecked((int)0xc177d0e3), unchecked((int)0xb32b6c16), 0x70a999b9, unchecked((int)0x9411fa48), unchecked((int)0xe9472264), unchecked((int)0xfca8c48c), unchecked((int)0xf0a01a3f), 0x7d56d82c, 0x3322ef90, 0x4987c74e, 0x38d9c1d1, unchecked((int)0xca8cfea2), unchecked((int)0xd498360b), unchecked((int)0xf5a6cf81), 0x7aa528de, unchecked((int)0xb7da268e), unchecked((int)0xad3fa4bf), 0x3a2ce49d, 0x78500d92, 0x5f6a9bcc, 0x7e546246, unchecked((int)0x8df6c213), unchecked((int)0xd890e8b8), 0x392e5ef7, unchecked((int)0xc382f5af), 0x5d9fbe80, unchecked((int)0xd0697c93), unchecked((int)0xd56fa92d), 0x25cfb312, unchecked((int)0xacc83b99), 0x1810a77d, unchecked((int)0x9ce86e63), 0x3bdb7bbb, 0x26cd0978, 0x596ef418, unchecked((int)0x9aec01b7), 0x4f83a89a, unchecked((int)0x95e6656e), unchecked((int)0xffaa7ee6), unchecked((int)0xbc2108cf), 0x15efe6e8, unchecked((int)0xe7bad99b), 0x6f4ace36, unchecked((int)0x9fead409), unchecked((int)0xb029d67c), unchecked((int)0xa431afb2), 0x3f2a3123, unchecked((int)0xa5c63094), unchecked((int)0xa235c066), 0x4e7437bc, unchecked((int)0x82fca6ca), unchecked((int)0x90e0b0d0), unchecked((int)0xa73315d8), 0x04f14a98, unchecked((int)0xec41f7da), unchecked((int)0xcd7f0e50), unchecked((int)0x91172ff6), 0x4d768dd6, unchecked((int)0xef434db0), unchecked((int)0xaacc544d), unchecked((int)0x96e4df04), unchecked((int)0xd19ee3b5), 0x6a4c1b88, 0x2cc1b81f, 0x65467f51, 0x5e9d04ea, unchecked((int)0x8c015d35), unchecked((int)0x87fa7374), 0x0bfb2e41, 0x67b35a1d, unchecked((int)0xdb9252d2), 0x10e93356, unchecked((int)0xd66d1347), unchecked((int)0xd79a8c61), unchecked((int)0xa1377a0c), unchecked((int)0xf8598e14), 0x13eb893c, unchecked((int)0xa9ceee27), 0x61b735c9, 0x1ce1ede5, 0x477a3cb1, unchecked((int)0xd29c59df), unchecked((int)0xf2553f73), 0x141879ce, unchecked((int)0xc773bf37), unchecked((int)0xf753eacd), unchecked((int)0xfd5f5baa), 0x3ddf146f, 0x447886db, unchecked((int)0xafca81f3), 0x68b93ec4, 0x24382c34, unchecked((int)0xa3c25f40), 0x1d1672c3, unchecked((int)0xe2bc0c25), 0x3c288b49, 0x0dff4195, unchecked((int)0xa8397101), 0x0c08deb3, unchecked((int)0xb4d89ce4), 0x566490c1, unchecked((int)0xcb7b6184), 0x32d570b6, 0x6c48745c, unchecked((int)0xb8d04257), 0x5150a7f4, 0x7e536541, 0x1ac3a417, 0x3a965e27, 0x3bcb6bab, 0x1ff1459d, unchecked((int)0xacab58fa), 0x4b9303e3, 0x2055fa30, unchecked((int)0xadf66d76), unchecked((int)0x889176cc), unchecked((int)0xf5254c02), 0x4ffcd7e5, unchecked((int)0xc5d7cb2a), 0x26804435, unchecked((int)0xb58fa362), unchecked((int)0xde495ab1), 0x25671bba, 0x45980eea, 0x5de1c0fe, unchecked((int)0xc302752f), unchecked((int)0x8112f04c), unchecked((int)0x8da39746), 0x6bc6f9d3, 0x03e75f8f, 0x15959c92, unchecked((int)0xbfeb7a6d), unchecked((int)0x95da5952), unchecked((int)0xd42d83be), 0x58d32174, 0x492969e0, unchecked((int)0x8e44c8c9), 0x756a89c2, unchecked((int)0xf478798e), unchecked((int)0x996b3e58), 0x27dd71b9, unchecked((int)0xbeb64fe1), unchecked((int)0xf017ad88), unchecked((int)0xc966ac20), 0x7db43ace, 0x63184adf, unchecked((int)0xe582311a), unchecked((int)0x97603351), 0x62457f53, unchecked((int)0xb1e07764), unchecked((int)0xbb84ae6b), unchecked((int)0xfe1ca081), unchecked((int)0xf9942b08), 0x70586848, unchecked((int)0x8f19fd45), unchecked((int)0x94876cde), 0x52b7f87b, unchecked((int)0xab23d373), 0x72e2024b, unchecked((int)0xe3578f1f), 0x662aab55, unchecked((int)0xb20728eb), 0x2f03c2b5, unchecked((int)0x869a7bc5), unchecked((int)0xd3a50837), 0x30f28728, 0x23b2a5bf, 0x02ba6a03, unchecked((int)0xed5c8216), unchecked((int)0x8a2b1ccf), unchecked((int)0xa792b479), unchecked((int)0xf3f0f207), 0x4ea1e269, 0x65cdf4da, 0x06d5be05, unchecked((int)0xd11f6234), unchecked((int)0xc48afea6), 0x349d532e, unchecked((int)0xa2a055f3), 0x0532e18a, unchecked((int)0xa475ebf6), 0x0b39ec83, 0x40aaef60, 0x5e069f71, unchecked((int)0xbd51106e), 0x3ef98a21, unchecked((int)0x963d06dd), unchecked((int)0xddae053e), 0x4d46bde6, unchecked((int)0x91b58d54), 0x71055dc4, 0x046fd406, 0x60ff1550, 0x1924fb98, unchecked((int)0xd697e9bd), unchecked((int)0x89cc4340), 0x67779ed9, unchecked((int)0xb0bd42e8), 0x07888b89, unchecked((int)0xe7385b19), 0x79dbeec8, unchecked((int)0xa1470a7c), 0x7ce90f42, unchecked((int)0xf8c91e84), 0x00000000, 0x09838680, 0x3248ed2b, 0x1eac7011, 0x6c4e725a, unchecked((int)0xfdfbff0e), 0x0f563885, 0x3d1ed5ae, 0x3627392d, 0x0a64d90f, 0x6821a65c, unchecked((int)0x9bd1545b), 0x243a2e36, 0x0cb1670a, unchecked((int)0x930fe757), unchecked((int)0xb4d296ee), 0x1b9e919b, unchecked((int)0x804fc5c0), 0x61a220dc, 0x5a694b77, 0x1c161a12, unchecked((int)0xe20aba93), unchecked((int)0xc0e52aa0), 0x3c43e022, 0x121d171b, 0x0e0b0d09, unchecked((int)0xf2adc78b), 0x2db9a8b6, 0x14c8a91e, 0x578519f1, unchecked((int)0xaf4c0775), unchecked((int)0xeebbdd99), unchecked((int)0xa3fd607f), unchecked((int)0xf79f2601), 0x5cbcf572, 0x44c53b66, 0x5b347efb, unchecked((int)0x8b762943), unchecked((int)0xcbdcc623), unchecked((int)0xb668fced), unchecked((int)0xb863f1e4), unchecked((int)0xd7cadc31), 0x42108563, 0x13402297, unchecked((int)0x842011c6), unchecked((int)0x857d244a), unchecked((int)0xd2f83dbb), unchecked((int)0xae1132f9), unchecked((int)0xc76da129), 0x1d4b2f9e, unchecked((int)0xdcf330b2), 0x0dec5286, 0x77d0e3c1, 0x2b6c16b3, unchecked((int)0xa999b970), 0x11fa4894, 0x472264e9, unchecked((int)0xa8c48cfc), unchecked((int)0xa01a3ff0), 0x56d82c7d, 0x22ef9033, unchecked((int)0x87c74e49), unchecked((int)0xd9c1d138), unchecked((int)0x8cfea2ca), unchecked((int)0x98360bd4), unchecked((int)0xa6cf81f5), unchecked((int)0xa528de7a), unchecked((int)0xda268eb7), 0x3fa4bfad, 0x2ce49d3a, 0x500d9278, 0x6a9bcc5f, 0x5462467e, unchecked((int)0xf6c2138d), unchecked((int)0x90e8b8d8), 0x2e5ef739, unchecked((int)0x82f5afc3), unchecked((int)0x9fbe805d), 0x697c93d0, 0x6fa92dd5, unchecked((int)0xcfb31225), unchecked((int)0xc83b99ac), 0x10a77d18, unchecked((int)0xe86e639c), unchecked((int)0xdb7bbb3b), unchecked((int)0xcd097826), 0x6ef41859, unchecked((int)0xec01b79a), unchecked((int)0x83a89a4f), unchecked((int)0xe6656e95), unchecked((int)0xaa7ee6ff), 0x2108cfbc, unchecked((int)0xefe6e815), unchecked((int)0xbad99be7), 0x4ace366f, unchecked((int)0xead4099f), 0x29d67cb0, 0x31afb2a4, 0x2a31233f, unchecked((int)0xc63094a5), 0x35c066a2, 0x7437bc4e, unchecked((int)0xfca6ca82), unchecked((int)0xe0b0d090), 0x3315d8a7, unchecked((int)0xf14a9804), 0x41f7daec, 0x7f0e50cd, 0x172ff691, 0x768dd64d, 0x434db0ef, unchecked((int)0xcc544daa), unchecked((int)0xe4df0496), unchecked((int)0x9ee3b5d1), 0x4c1b886a, unchecked((int)0xc1b81f2c), 0x467f5165, unchecked((int)0x9d04ea5e), 0x015d358c, unchecked((int)0xfa737487), unchecked((int)0xfb2e410b), unchecked((int)0xb35a1d67), unchecked((int)0x9252d2db), unchecked((int)0xe9335610), 0x6d1347d6, unchecked((int)0x9a8c61d7), 0x377a0ca1, 0x598e14f8, unchecked((int)0xeb893c13), unchecked((int)0xceee27a9), unchecked((int)0xb735c961), unchecked((int)0xe1ede51c), 0x7a3cb147, unchecked((int)0x9c59dfd2), 0x553f73f2, 0x1879ce14, 0x73bf37c7, 0x53eacdf7, 0x5f5baafd, unchecked((int)0xdf146f3d), 0x7886db44, unchecked((int)0xca81f3af), unchecked((int)0xb93ec468), 0x382c3424, unchecked((int)0xc25f40a3), 0x1672c31d, unchecked((int)0xbc0c25e2), 0x288b493c, unchecked((int)0xff41950d), 0x397101a8, 0x08deb30c, unchecked((int)0xd89ce4b4), 0x6490c156, 0x7b6184cb, unchecked((int)0xd570b632), 0x48745c6c, unchecked((int)0xd04257b8)};

		private static int shift(int r, int shift)
		{
			return ((int)((uint)r >> shift)) | (r << -shift);
		}

		/* multiply four bytes in GF(2^8) by 'x' {02} in parallel */

		private const int m1 = unchecked((int)0x80808080);
		private const int m2 = 0x7f7f7f7f;
		private const int m3 = 0x0000001b;
		private const int m4 = unchecked((int)0xC0C0C0C0);
		private const int m5 = 0x3f3f3f3f;

		private static int FFmulX(int x)
		{
			return (((x & m2) << 1) ^ (((int)((uint)(x & m1) >> 7)) * m3));
		}

		private static int FFmulX2(int x)
		{
			int t0 = (x & m5) << 2;
			int t1 = (x & m4);
				t1 ^= ((int)((uint)t1 >> 1));
			return t0 ^ ((int)((uint)t1 >> 2)) ^ ((int)((uint)t1 >> 5));
		}

		/* 
		   The following defines provide alternative definitions of FFmulX that might
		   give improved performance if a fast 32-bit multiply is not available.
		   
		   private int FFmulX(int x) { int u = x & m1; u |= (u >> 1); return ((x & m2) << 1) ^ ((u >>> 3) | (u >>> 6)); } 
		   private static final int  m4 = 0x1b1b1b1b;
		   private int FFmulX(int x) { int u = x & m1; return ((x & m2) << 1) ^ ((u - (u >>> 7)) & m4); } 
	
		*/

		private static int inv_mcol(int x)
		{
			int t0, t1;
			t0 = x;
			t1 = t0 ^ shift(t0, 8);
			t0 ^= FFmulX(t1);
			t1 ^= FFmulX2(t0);
			t0 ^= t1 ^ shift(t1, 16);
			return t0;
		}

		private static int subWord(int x)
		{
			int i0 = x, i1 = (int)((uint)x >> 8), i2 = (int)((uint)x >> 16), i3 = (int)((uint)x >> 24);
			i0 = S[i0 & 255] & 255;
			i1 = S[i1 & 255] & 255;
			i2 = S[i2 & 255] & 255;
			i3 = S[i3 & 255] & 255;
			return i0 | i1 << 8 | i2 << 16 | i3 << 24;
		}

		/// <summary>
		/// Calculate the necessary round keys
		/// The number of calculations depends on key size and block size
		/// AES specified a fixed block size of 128 bits and key sizes 128/192/256 bits
		/// This code is written assuming those are the only possible values
		/// </summary>
		private int[][] generateWorkingKey(byte[] key, bool forEncryption)
		{
			int keyLen = key.Length;
			if (keyLen < 16 || keyLen > 32 || (keyLen & 7) != 0)
			{
				throw new IllegalArgumentException("Key length not 128/192/256 bits.");
			}

			int KC = (int)((uint)keyLen >> 2);
			ROUNDS = KC + 6; // This is not always true for the generalized Rijndael that allows larger block sizes
			int[][] W = RectangularArrays.ReturnRectangularIntArray(ROUNDS + 1, 4); // 4 words in a block

			switch (KC)
			{
			case 4:
			{
				int t0 = Pack.littleEndianToInt(key, 0);
				W[0][0] = t0;
				int t1 = Pack.littleEndianToInt(key, 4);
				W[0][1] = t1;
				int t2 = Pack.littleEndianToInt(key, 8);
				W[0][2] = t2;
				int t3 = Pack.littleEndianToInt(key, 12);
				W[0][3] = t3;

				for (int i = 1; i <= 10; ++i)
				{
					int u = subWord(shift(t3, 8)) ^ rcon[i - 1];
					t0 ^= u;
					W[i][0] = t0;
					t1 ^= t0;
					W[i][1] = t1;
					t2 ^= t1;
					W[i][2] = t2;
					t3 ^= t2;
					W[i][3] = t3;
				}

				break;
			}
			case 6:
			{
				int t0 = Pack.littleEndianToInt(key, 0);
				W[0][0] = t0;
				int t1 = Pack.littleEndianToInt(key, 4);
				W[0][1] = t1;
				int t2 = Pack.littleEndianToInt(key, 8);
				W[0][2] = t2;
				int t3 = Pack.littleEndianToInt(key, 12);
				W[0][3] = t3;
				int t4 = Pack.littleEndianToInt(key, 16);
				W[1][0] = t4;
				int t5 = Pack.littleEndianToInt(key, 20);
				W[1][1] = t5;

				int rcon = 1;
				int u = subWord(shift(t5, 8)) ^ rcon;
				rcon <<= 1;
				t0 ^= u;
				W[1][2] = t0;
				t1 ^= t0;
				W[1][3] = t1;
				t2 ^= t1;
				W[2][0] = t2;
				t3 ^= t2;
				W[2][1] = t3;
				t4 ^= t3;
				W[2][2] = t4;
				t5 ^= t4;
				W[2][3] = t5;

				for (int i = 3; i < 12; i += 3)
				{
					u = subWord(shift(t5, 8)) ^ rcon;
					rcon <<= 1;
					t0 ^= u;
					W[i][0] = t0;
					t1 ^= t0;
					W[i][1] = t1;
					t2 ^= t1;
					W[i][2] = t2;
					t3 ^= t2;
					W[i][3] = t3;
					t4 ^= t3;
					W[i + 1][0] = t4;
					t5 ^= t4;
					W[i + 1][1] = t5;
					u = subWord(shift(t5, 8)) ^ rcon;
					rcon <<= 1;
					t0 ^= u;
					W[i + 1][2] = t0;
					t1 ^= t0;
					W[i + 1][3] = t1;
					t2 ^= t1;
					W[i + 2][0] = t2;
					t3 ^= t2;
					W[i + 2][1] = t3;
					t4 ^= t3;
					W[i + 2][2] = t4;
					t5 ^= t4;
					W[i + 2][3] = t5;
				}

				u = subWord(shift(t5, 8)) ^ rcon;
				t0 ^= u;
				W[12][0] = t0;
				t1 ^= t0;
				W[12][1] = t1;
				t2 ^= t1;
				W[12][2] = t2;
				t3 ^= t2;
				W[12][3] = t3;

				break;
			}
			case 8:
			{
				int t0 = Pack.littleEndianToInt(key, 0);
				W[0][0] = t0;
				int t1 = Pack.littleEndianToInt(key, 4);
				W[0][1] = t1;
				int t2 = Pack.littleEndianToInt(key, 8);
				W[0][2] = t2;
				int t3 = Pack.littleEndianToInt(key, 12);
				W[0][3] = t3;
				int t4 = Pack.littleEndianToInt(key, 16);
				W[1][0] = t4;
				int t5 = Pack.littleEndianToInt(key, 20);
				W[1][1] = t5;
				int t6 = Pack.littleEndianToInt(key, 24);
				W[1][2] = t6;
				int t7 = Pack.littleEndianToInt(key, 28);
				W[1][3] = t7;

				int u, rcon = 1;

				for (int i = 2; i < 14; i += 2)
				{
					u = subWord(shift(t7, 8)) ^ rcon;
					rcon <<= 1;
					t0 ^= u;
					W[i][0] = t0;
					t1 ^= t0;
					W[i][1] = t1;
					t2 ^= t1;
					W[i][2] = t2;
					t3 ^= t2;
					W[i][3] = t3;
					u = subWord(t3);
					t4 ^= u;
					W[i + 1][0] = t4;
					t5 ^= t4;
					W[i + 1][1] = t5;
					t6 ^= t5;
					W[i + 1][2] = t6;
					t7 ^= t6;
					W[i + 1][3] = t7;
				}

				u = subWord(shift(t7, 8)) ^ rcon;
				t0 ^= u;
				W[14][0] = t0;
				t1 ^= t0;
				W[14][1] = t1;
				t2 ^= t1;
				W[14][2] = t2;
				t3 ^= t2;
				W[14][3] = t3;

				break;
			}
			default:
			{
				throw new IllegalStateException("Should never get here");
			}
			}

			if (!forEncryption)
			{
				for (int j = 1; j < ROUNDS; j++)
				{
					for (int i = 0; i < 4; i++)
					{
						W[j][i] = inv_mcol(W[j][i]);
					}
				}
			}

			return W;
		}

		private int ROUNDS;
		private int[][] WorkingKey = null;
		private int C0, C1, C2, C3;
		private bool forEncryption;

		private const int BLOCK_SIZE = 16;

		/// <summary>
		/// default constructor - 128 bit block size.
		/// </summary>
		public AESFastEngine()
		{
		}

		/// <summary>
		/// initialise an AES cipher.
		/// </summary>
		/// <param name="forEncryption"> whether or not we are for encryption. </param>
		/// <param name="params"> the parameters required to set up the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			if (@params is KeyParameter)
			{
				WorkingKey = generateWorkingKey(((KeyParameter)@params).getKey(), forEncryption);
				this.forEncryption = forEncryption;
				return;
			}

			throw new IllegalArgumentException("invalid parameter passed to AES init - " + @params.GetType().getName());
		}

		public virtual string getAlgorithmName()
		{
			return "AES";
		}

		public virtual int getBlockSize()
		{
			return BLOCK_SIZE;
		}

		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if (WorkingKey == null)
			{
				throw new IllegalStateException("AES engine not initialised");
			}

			if ((inOff + (32 / 2)) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOff + (32 / 2)) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			unpackBlock(@in, inOff);

			if (forEncryption)
			{
				encryptBlock(WorkingKey);
			}
			else
			{
				decryptBlock(WorkingKey);
			}

			packBlock(@out, outOff);

			return BLOCK_SIZE;
		}

		public virtual void reset()
		{
		}

		private void unpackBlock(byte[] bytes, int off)
		{
			this.C0 = Pack.littleEndianToInt(bytes, off);
			this.C1 = Pack.littleEndianToInt(bytes, off + 4);
			this.C2 = Pack.littleEndianToInt(bytes, off + 8);
			this.C3 = Pack.littleEndianToInt(bytes, off + 12);
		}

		private void packBlock(byte[] bytes, int off)
		{
			Pack.intToLittleEndian(this.C0, bytes, off);
			Pack.intToLittleEndian(this.C1, bytes, off + 4);
			Pack.intToLittleEndian(this.C2, bytes, off + 8);
			Pack.intToLittleEndian(this.C3, bytes, off + 12);
		}

		private void encryptBlock(int[][] KW)
		{
			int t0 = this.C0 ^ KW[0][0];
			int t1 = this.C1 ^ KW[0][1];
			int t2 = this.C2 ^ KW[0][2];

			/*
			 * Fast engine has precomputed rotr(T0, 8/16/24) tables T1/T2/T3.
			 *
			 * Placing all precomputes in one array requires offsets additions for 8/16/24 rotations but
			 * avoids additional array range checks on 3 more arrays (which on HotSpot are more
			 * expensive than the offset additions).
			 */
			int r = 1, r0, r1, r2, r3 = this.C3 ^ KW[0][3];
			int i0, i1, i2, i3;

			while (r < ROUNDS - 1)
			{
				i0 = t0;
				i1 = (int)((uint)t1 >> 8);
				i2 = (int)((uint)t2 >> 16);
				i3 = (int)((uint)r3 >> 24);
				i0 &= 255;
				i1 &= 255;
				i2 &= 255;
				i3 &= 255;
				r0 = T[i0] ^ T[256 + i1] ^ T[512 + i2] ^ T[768 + i3] ^ KW[r][0];

				i0 = t1;
				i1 = (int)((uint)t2 >> 8);
				i2 = (int)((uint)r3 >> 16);
				i3 = (int)((uint)t0 >> 24);
				i0 &= 255;
				i1 &= 255;
				i2 &= 255;
				i3 &= 255;
				r1 = T[i0] ^ T[256 + i1] ^ T[512 + i2] ^ T[768 + i3] ^ KW[r][1];

				i0 = t2;
				i1 = (int)((uint)r3 >> 8);
				i2 = (int)((uint)t0 >> 16);
				i3 = (int)((uint)t1 >> 24);
				i0 &= 255;
				i1 &= 255;
				i2 &= 255;
				i3 &= 255;
				r2 = T[i0] ^ T[256 + i1] ^ T[512 + i2] ^ T[768 + i3] ^ KW[r][2];

				i0 = r3;
				i1 = (int)((uint)t0 >> 8);
				i2 = (int)((uint)t1 >> 16);
				i3 = (int)((uint)t2 >> 24);
				i0 &= 255;
				i1 &= 255;
				i2 &= 255;
				i3 &= 255;
				r3 = T[i0] ^ T[256 + i1] ^ T[512 + i2] ^ T[768 + i3] ^ KW[r++][3];

				i0 = r0;
				i1 = (int)((uint)r1 >> 8);
				i2 = (int)((uint)r2 >> 16);
				i3 = (int)((uint)r3 >> 24);
				i0 &= 255;
				i1 &= 255;
				i2 &= 255;
				i3 &= 255;
				t0 = T[i0] ^ T[256 + i1] ^ T[512 + i2] ^ T[768 + i3] ^ KW[r][0];

				i0 = r1;
				i1 = (int)((uint)r2 >> 8);
				i2 = (int)((uint)r3 >> 16);
				i3 = (int)((uint)r0 >> 24);
				i0 &= 255;
				i1 &= 255;
				i2 &= 255;
				i3 &= 255;
				t1 = T[i0] ^ T[256 + i1] ^ T[512 + i2] ^ T[768 + i3] ^ KW[r][1];

				i0 = r2;
				i1 = (int)((uint)r3 >> 8);
				i2 = (int)((uint)r0 >> 16);
				i3 = (int)((uint)r1 >> 24);
				i0 &= 255;
				i1 &= 255;
				i2 &= 255;
				i3 &= 255;
				t2 = T[i0] ^ T[256 + i1] ^ T[512 + i2] ^ T[768 + i3] ^ KW[r][2];

				i0 = r3;
				i1 = (int)((uint)r0 >> 8);
				i2 = (int)((uint)r1 >> 16);
				i3 = (int)((uint)r2 >> 24);
				i0 &= 255;
				i1 &= 255;
				i2 &= 255;
				i3 &= 255;
				r3 = T[i0] ^ T[256 + i1] ^ T[512 + i2] ^ T[768 + i3] ^ KW[r++][3];
			}

			i0 = t0;
			i1 = (int)((uint)t1 >> 8);
			i2 = (int)((uint)t2 >> 16);
			i3 = (int)((uint)r3 >> 24);
			i0 &= 255;
			i1 &= 255;
			i2 &= 255;
			i3 &= 255;
			r0 = T[i0] ^ T[256 + i1] ^ T[512 + i2] ^ T[768 + i3] ^ KW[r][0];

			i0 = t1;
			i1 = (int)((uint)t2 >> 8);
			i2 = (int)((uint)r3 >> 16);
			i3 = (int)((uint)t0 >> 24);
			i0 &= 255;
			i1 &= 255;
			i2 &= 255;
			i3 &= 255;
			r1 = T[i0] ^ T[256 + i1] ^ T[512 + i2] ^ T[768 + i3] ^ KW[r][1];

			i0 = t2;
			i1 = (int)((uint)r3 >> 8);
			i2 = (int)((uint)t0 >> 16);
			i3 = (int)((uint)t1 >> 24);
			i0 &= 255;
			i1 &= 255;
			i2 &= 255;
			i3 &= 255;
			r2 = T[i0] ^ T[256 + i1] ^ T[512 + i2] ^ T[768 + i3] ^ KW[r][2];

			i0 = r3;
			i1 = (int)((uint)t0 >> 8);
			i2 = (int)((uint)t1 >> 16);
			i3 = (int)((uint)t2 >> 24);
			i0 &= 255;
			i1 &= 255;
			i2 &= 255;
			i3 &= 255;
			r3 = T[i0] ^ T[256 + i1] ^ T[512 + i2] ^ T[768 + i3] ^ KW[r++][3];

			// the final round's table is a simple function of S so we don't use a whole other four tables for it

			i0 = r0;
			i1 = (int)((uint)r1 >> 8);
			i2 = (int)((uint)r2 >> 16);
			i3 = (int)((uint)r3 >> 24);
			i0 = S[i0 & 255] & 255;
			i1 = S[i1 & 255] & 255;
			i2 = S[i2 & 255] & 255;
			i3 = S[i3 & 255] & 255;
			this.C0 = i0 ^ i1 << 8 ^ i2 << 16 ^ i3 << 24 ^ KW[r][0];

			i0 = r1;
			i1 = (int)((uint)r2 >> 8);
			i2 = (int)((uint)r3 >> 16);
			i3 = (int)((uint)r0 >> 24);
			i0 = S[i0 & 255] & 255;
			i1 = S[i1 & 255] & 255;
			i2 = S[i2 & 255] & 255;
			i3 = S[i3 & 255] & 255;
			this.C1 = i0 ^ i1 << 8 ^ i2 << 16 ^ i3 << 24 ^ KW[r][1];

			i0 = r2;
			i1 = (int)((uint)r3 >> 8);
			i2 = (int)((uint)r0 >> 16);
			i3 = (int)((uint)r1 >> 24);
			i0 = S[i0 & 255] & 255;
			i1 = S[i1 & 255] & 255;
			i2 = S[i2 & 255] & 255;
			i3 = S[i3 & 255] & 255;
			this.C2 = i0 ^ i1 << 8 ^ i2 << 16 ^ i3 << 24 ^ KW[r][2];

			i0 = r3;
			i1 = (int)((uint)r0 >> 8);
			i2 = (int)((uint)r1 >> 16);
			i3 = (int)((uint)r2 >> 24);
			i0 = S[i0 & 255] & 255;
			i1 = S[i1 & 255] & 255;
			i2 = S[i2 & 255] & 255;
			i3 = S[i3 & 255] & 255;
			this.C3 = i0 ^ i1 << 8 ^ i2 << 16 ^ i3 << 24 ^ KW[r][3];
		}

		private void decryptBlock(int[][] KW)
		{
			int t0 = this.C0 ^ KW[ROUNDS][0];
			int t1 = this.C1 ^ KW[ROUNDS][1];
			int t2 = this.C2 ^ KW[ROUNDS][2];

			int r = ROUNDS - 1, r0, r1, r2, r3 = this.C3 ^ KW[ROUNDS][3];
			int i0, i1, i2, i3;

			while (r > 1)
			{
				i0 = t0;
				i1 = (int)((uint)r3 >> 8);
				i2 = (int)((uint)t2 >> 16);
				i3 = (int)((uint)t1 >> 24);
				i0 &= 255;
				i1 &= 255;
				i2 &= 255;
				i3 &= 255;
				r0 = Tinv[i0] ^ Tinv[256 + i1] ^ Tinv[512 + i2] ^ Tinv[768 + i3] ^ KW[r][0];

				i0 = t1;
				i1 = (int)((uint)t0 >> 8);
				i2 = (int)((uint)r3 >> 16);
				i3 = (int)((uint)t2 >> 24);
				i0 &= 255;
				i1 &= 255;
				i2 &= 255;
				i3 &= 255;
				r1 = Tinv[i0] ^ Tinv[256 + i1] ^ Tinv[512 + i2] ^ Tinv[768 + i3] ^ KW[r][1];

				i0 = t2;
				i1 = (int)((uint)t1 >> 8);
				i2 = (int)((uint)t0 >> 16);
				i3 = (int)((uint)r3 >> 24);
				i0 &= 255;
				i1 &= 255;
				i2 &= 255;
				i3 &= 255;
				r2 = Tinv[i0] ^ Tinv[256 + i1] ^ Tinv[512 + i2] ^ Tinv[768 + i3] ^ KW[r][2];

				i0 = r3;
				i1 = (int)((uint)t2 >> 8);
				i2 = (int)((uint)t1 >> 16);
				i3 = (int)((uint)t0 >> 24);
				i0 &= 255;
				i1 &= 255;
				i2 &= 255;
				i3 &= 255;
				r3 = Tinv[i0] ^ Tinv[256 + i1] ^ Tinv[512 + i2] ^ Tinv[768 + i3] ^ KW[r--][3];

				i0 = r0;
				i1 = (int)((uint)r3 >> 8);
				i2 = (int)((uint)r2 >> 16);
				i3 = (int)((uint)r1 >> 24);
				i0 &= 255;
				i1 &= 255;
				i2 &= 255;
				i3 &= 255;
				t0 = Tinv[i0] ^ Tinv[256 + i1] ^ Tinv[512 + i2] ^ Tinv[768 + i3] ^ KW[r][0];

				i0 = r1;
				i1 = (int)((uint)r0 >> 8);
				i2 = (int)((uint)r3 >> 16);
				i3 = (int)((uint)r2 >> 24);
				i0 &= 255;
				i1 &= 255;
				i2 &= 255;
				i3 &= 255;
				t1 = Tinv[i0] ^ Tinv[256 + i1] ^ Tinv[512 + i2] ^ Tinv[768 + i3] ^ KW[r][1];

				i0 = r2;
				i1 = (int)((uint)r1 >> 8);
				i2 = (int)((uint)r0 >> 16);
				i3 = (int)((uint)r3 >> 24);
				i0 &= 255;
				i1 &= 255;
				i2 &= 255;
				i3 &= 255;
				t2 = Tinv[i0] ^ Tinv[256 + i1] ^ Tinv[512 + i2] ^ Tinv[768 + i3] ^ KW[r][2];

				i0 = r3;
				i1 = (int)((uint)r2 >> 8);
				i2 = (int)((uint)r1 >> 16);
				i3 = (int)((uint)r0 >> 24);
				i0 &= 255;
				i1 &= 255;
				i2 &= 255;
				i3 &= 255;
				r3 = Tinv[i0] ^ Tinv[256 + i1] ^ Tinv[512 + i2] ^ Tinv[768 + i3] ^ KW[r--][3];
			}

			i0 = t0;
			i1 = (int)((uint)r3 >> 8);
			i2 = (int)((uint)t2 >> 16);
			i3 = (int)((uint)t1 >> 24);
			i0 &= 255;
			i1 &= 255;
			i2 &= 255;
			i3 &= 255;
			r0 = Tinv[i0] ^ Tinv[256 + i1] ^ Tinv[512 + i2] ^ Tinv[768 + i3] ^ KW[1][0];

			i0 = t1;
			i1 = (int)((uint)t0 >> 8);
			i2 = (int)((uint)r3 >> 16);
			i3 = (int)((uint)t2 >> 24);
			i0 &= 255;
			i1 &= 255;
			i2 &= 255;
			i3 &= 255;
			r1 = Tinv[i0] ^ Tinv[256 + i1] ^ Tinv[512 + i2] ^ Tinv[768 + i3] ^ KW[1][1];

			i0 = t2;
			i1 = (int)((uint)t1 >> 8);
			i2 = (int)((uint)t0 >> 16);
			i3 = (int)((uint)r3 >> 24);
			i0 &= 255;
			i1 &= 255;
			i2 &= 255;
			i3 &= 255;
			r2 = Tinv[i0] ^ Tinv[256 + i1] ^ Tinv[512 + i2] ^ Tinv[768 + i3] ^ KW[1][2];

			i0 = r3;
			i1 = (int)((uint)t2 >> 8);
			i2 = (int)((uint)t1 >> 16);
			i3 = (int)((uint)t0 >> 24);
			i0 &= 255;
			i1 &= 255;
			i2 &= 255;
			i3 &= 255;
			r3 = Tinv[i0] ^ Tinv[256 + i1] ^ Tinv[512 + i2] ^ Tinv[768 + i3] ^ KW[1][3];

			// the final round's table is a simple function of Si so we don't use a whole other four tables for it

			i0 = r0;
			i1 = (int)((uint)r3 >> 8);
			i2 = (int)((uint)r2 >> 16);
			i3 = (int)((uint)r1 >> 24);
			i0 = Si[i0 & 255] & 255;
			i1 = Si[i1 & 255] & 255;
			i2 = Si[i2 & 255] & 255;
			i3 = Si[i3 & 255] & 255;
			this.C0 = i0 ^ i1 << 8 ^ i2 << 16 ^ i3 << 24 ^ KW[0][0];

			i0 = r1;
			i1 = (int)((uint)r0 >> 8);
			i2 = (int)((uint)r3 >> 16);
			i3 = (int)((uint)r2 >> 24);
			i0 = Si[i0 & 255] & 255;
			i1 = Si[i1 & 255] & 255;
			i2 = Si[i2 & 255] & 255;
			i3 = Si[i3 & 255] & 255;
			this.C1 = i0 ^ i1 << 8 ^ i2 << 16 ^ i3 << 24 ^ KW[0][1];

			i0 = r2;
			i1 = (int)((uint)r1 >> 8);
			i2 = (int)((uint)r0 >> 16);
			i3 = (int)((uint)r3 >> 24);
			i0 = Si[i0 & 255] & 255;
			i1 = Si[i1 & 255] & 255;
			i2 = Si[i2 & 255] & 255;
			i3 = Si[i3 & 255] & 255;
			this.C2 = i0 ^ i1 << 8 ^ i2 << 16 ^ i3 << 24 ^ KW[0][2];

			i0 = r3;
			i1 = (int)((uint)r2 >> 8);
			i2 = (int)((uint)r1 >> 16);
			i3 = (int)((uint)r0 >> 24);
			i0 = Si[i0 & 255] & 255;
			i1 = Si[i1 & 255] & 255;
			i2 = Si[i2 & 255] & 255;
			i3 = Si[i3 & 255] & 255;
			this.C3 = i0 ^ i1 << 8 ^ i2 << 16 ^ i3 << 24 ^ KW[0][3];
		}
	}

}