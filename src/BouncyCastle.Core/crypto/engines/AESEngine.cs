using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;
	using Pack = org.bouncycastle.util.Pack;

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
	/// the contents of the first.
	/// 
	/// The slowest version uses no static tables at all and computes the values in each round.
	/// </para>
	/// <para>
	/// This file contains the middle performance version with 2Kbytes of static tables for round precomputation.
	/// 
	/// </para>
	/// </summary>
	public class AESEngine : BlockCipher
	{
		// The S box
		private static readonly byte[] S = new byte[] {99, 124, 119, 123, unchecked(242), 107, 111, unchecked(197), 48, 1, 103, 43, unchecked(254), unchecked(215), unchecked(171), 118, unchecked(202), unchecked(130), unchecked(201), 125, unchecked(250), 89, 71, unchecked(240), unchecked(173), unchecked(212), unchecked(162), unchecked(175), unchecked(156), unchecked(164), 114, unchecked(192), unchecked(183), unchecked(253), unchecked(147), 38, 54, 63, unchecked(247), unchecked(204), 52, unchecked(165), unchecked(229), unchecked(241), 113, unchecked(216), 49, 21, 4, unchecked(199), 35, unchecked(195), 24, unchecked(150), 5, unchecked(154), 7, 18, unchecked(128), unchecked(226), unchecked(235), 39, unchecked(178), 117, 9, unchecked(131), 44, 26, 27, 110, 90, unchecked(160), 82, 59, unchecked(214), unchecked(179), 41, unchecked(227), 47, unchecked(132), 83, unchecked(209), 0, unchecked(237), 32, unchecked(252), unchecked(177), 91, 106, unchecked(203), unchecked(190), 57, 74, 76, 88, unchecked(207), unchecked(208), unchecked(239), unchecked(170), unchecked(251), 67, 77, 51, unchecked(133), 69, unchecked(249), 2, 127, 80, 60, unchecked(159), unchecked(168), 81, unchecked(163), 64, unchecked(143), unchecked(146), unchecked(157), 56, unchecked(245), unchecked(188), unchecked(182), unchecked(218), 33, 16, unchecked(255), unchecked(243), unchecked(210), unchecked(205), 12, 19, unchecked(236), 95, unchecked(151), 68, 23, unchecked(196), unchecked(167), 126, 61, 100, 93, 25, 115, 96, unchecked(129), 79, unchecked(220), 34, 42, unchecked(144), unchecked(136), 70, unchecked(238), unchecked(184), 20, unchecked(222), 94, 11, unchecked(219), unchecked(224), 50, 58, 10, 73, 6, 36, 92, unchecked(194), unchecked(211), unchecked(172), 98, unchecked(145), unchecked(149), unchecked(228), 121, unchecked(231), unchecked(200), 55, 109, unchecked(141), unchecked(213), 78, unchecked(169), 108, 86, unchecked(244), unchecked(234), 101, 122, unchecked(174), 8, unchecked(186), 120, 37, 46, 28, unchecked(166), unchecked(180), unchecked(198), unchecked(232), unchecked(221), 116, 31, 75, unchecked(189), unchecked(139), unchecked(138), 112, 62, unchecked(181), 102, 72, 3, unchecked(246), 14, 97, 53, 87, unchecked(185), unchecked(134), unchecked(193), 29, unchecked(158), unchecked(225), unchecked(248), unchecked(152), 17, 105, unchecked(217), unchecked(142), unchecked(148), unchecked(155), 30, unchecked(135), unchecked(233), unchecked(206), 85, 40, unchecked(223), unchecked(140), unchecked(161), unchecked(137), 13, unchecked(191), unchecked(230), 66, 104, 65, unchecked(153), 45, 15, unchecked(176), 84, unchecked(187), 22};

		// The inverse S-box
		private static readonly byte[] Si = new byte[] {82, 9, 106, unchecked(213), 48, 54, unchecked(165), 56, unchecked(191), 64, unchecked(163), unchecked(158), unchecked(129), unchecked(243), unchecked(215), unchecked(251), 124, unchecked(227), 57, unchecked(130), unchecked(155), 47, unchecked(255), unchecked(135), 52, unchecked(142), 67, 68, unchecked(196), unchecked(222), unchecked(233), unchecked(203), 84, 123, unchecked(148), 50, unchecked(166), unchecked(194), 35, 61, unchecked(238), 76, unchecked(149), 11, 66, unchecked(250), unchecked(195), 78, 8, 46, unchecked(161), 102, 40, unchecked(217), 36, unchecked(178), 118, 91, unchecked(162), 73, 109, unchecked(139), unchecked(209), 37, 114, unchecked(248), unchecked(246), 100, unchecked(134), 104, unchecked(152), 22, unchecked(212), unchecked(164), 92, unchecked(204), 93, 101, unchecked(182), unchecked(146), 108, 112, 72, 80, unchecked(253), unchecked(237), unchecked(185), unchecked(218), 94, 21, 70, 87, unchecked(167), unchecked(141), unchecked(157), unchecked(132), unchecked(144), unchecked(216), unchecked(171), 0, unchecked(140), unchecked(188), unchecked(211), 10, unchecked(247), unchecked(228), 88, 5, unchecked(184), unchecked(179), 69, 6, unchecked(208), 44, 30, unchecked(143), unchecked(202), 63, 15, 2, unchecked(193), unchecked(175), unchecked(189), 3, 1, 19, unchecked(138), 107, 58, unchecked(145), 17, 65, 79, 103, unchecked(220), unchecked(234), unchecked(151), unchecked(242), unchecked(207), unchecked(206), unchecked(240), unchecked(180), unchecked(230), 115, unchecked(150), unchecked(172), 116, 34, unchecked(231), unchecked(173), 53, unchecked(133), unchecked(226), unchecked(249), 55, unchecked(232), 28, 117, unchecked(223), 110, 71, unchecked(241), 26, 113, 29, 41, unchecked(197), unchecked(137), 111, unchecked(183), 98, 14, unchecked(170), 24, unchecked(190), 27, unchecked(252), 86, 62, 75, unchecked(198), unchecked(210), 121, 32, unchecked(154), unchecked(219), unchecked(192), unchecked(254), 120, unchecked(205), 90, unchecked(244), 31, unchecked(221), unchecked(168), 51, unchecked(136), 7, unchecked(199), 49, unchecked(177), 18, 16, 89, 39, unchecked(128), unchecked(236), 95, 96, 81, 127, unchecked(169), 25, unchecked(181), 74, 13, 45, unchecked(229), 122, unchecked(159), unchecked(147), unchecked(201), unchecked(156), unchecked(239), unchecked(160), unchecked(224), 59, 77, unchecked(174), 42, unchecked(245), unchecked(176), unchecked(200), unchecked(235), unchecked(187), 60, unchecked(131), 83, unchecked(153), 97, 23, 43, 4, 126, unchecked(186), 119, unchecked(214), 38, unchecked(225), 105, 20, 99, 85, 33, 12, 125};

		// vector used in calculating key schedule (powers of x in GF(256))
		private static readonly int[] rcon = new int[] {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91};

		// precomputation tables of calculations for rounds
		private static readonly int[] T0 = new int[] {unchecked((int)0xa56363c6), unchecked((int)0x847c7cf8), unchecked((int)0x997777ee), unchecked((int)0x8d7b7bf6), 0x0df2f2ff, unchecked((int)0xbd6b6bd6), unchecked((int)0xb16f6fde), 0x54c5c591, 0x50303060, 0x03010102, unchecked((int)0xa96767ce), 0x7d2b2b56, 0x19fefee7, 0x62d7d7b5, unchecked((int)0xe6abab4d), unchecked((int)0x9a7676ec), 0x45caca8f, unchecked((int)0x9d82821f), 0x40c9c989, unchecked((int)0x877d7dfa), 0x15fafaef, unchecked((int)0xeb5959b2), unchecked((int)0xc947478e), 0x0bf0f0fb, unchecked((int)0xecadad41), 0x67d4d4b3, unchecked((int)0xfda2a25f), unchecked((int)0xeaafaf45), unchecked((int)0xbf9c9c23), unchecked((int)0xf7a4a453), unchecked((int)0x967272e4), 0x5bc0c09b, unchecked((int)0xc2b7b775), 0x1cfdfde1, unchecked((int)0xae93933d), 0x6a26264c, 0x5a36366c, 0x413f3f7e, 0x02f7f7f5, 0x4fcccc83, 0x5c343468, unchecked((int)0xf4a5a551), 0x34e5e5d1, 0x08f1f1f9, unchecked((int)0x937171e2), 0x73d8d8ab, 0x53313162, 0x3f15152a, 0x0c040408, 0x52c7c795, 0x65232346, 0x5ec3c39d, 0x28181830, unchecked((int)0xa1969637), 0x0f05050a, unchecked((int)0xb59a9a2f), 0x0907070e, 0x36121224, unchecked((int)0x9b80801b), 0x3de2e2df, 0x26ebebcd, 0x6927274e, unchecked((int)0xcdb2b27f), unchecked((int)0x9f7575ea), 0x1b090912, unchecked((int)0x9e83831d), 0x742c2c58, 0x2e1a1a34, 0x2d1b1b36, unchecked((int)0xb26e6edc), unchecked((int)0xee5a5ab4), unchecked((int)0xfba0a05b), unchecked((int)0xf65252a4), 0x4d3b3b76, 0x61d6d6b7, unchecked((int)0xceb3b37d), 0x7b292952, 0x3ee3e3dd, 0x712f2f5e, unchecked((int)0x97848413), unchecked((int)0xf55353a6), 0x68d1d1b9, 0x00000000, 0x2cededc1, 0x60202040, 0x1ffcfce3, unchecked((int)0xc8b1b179), unchecked((int)0xed5b5bb6), unchecked((int)0xbe6a6ad4), 0x46cbcb8d, unchecked((int)0xd9bebe67), 0x4b393972, unchecked((int)0xde4a4a94), unchecked((int)0xd44c4c98), unchecked((int)0xe85858b0), 0x4acfcf85, 0x6bd0d0bb, 0x2aefefc5, unchecked((int)0xe5aaaa4f), 0x16fbfbed, unchecked((int)0xc5434386), unchecked((int)0xd74d4d9a), 0x55333366, unchecked((int)0x94858511), unchecked((int)0xcf45458a), 0x10f9f9e9, 0x06020204, unchecked((int)0x817f7ffe), unchecked((int)0xf05050a0), 0x443c3c78, unchecked((int)0xba9f9f25), unchecked((int)0xe3a8a84b), unchecked((int)0xf35151a2), unchecked((int)0xfea3a35d), unchecked((int)0xc0404080), unchecked((int)0x8a8f8f05), unchecked((int)0xad92923f), unchecked((int)0xbc9d9d21), 0x48383870, 0x04f5f5f1, unchecked((int)0xdfbcbc63), unchecked((int)0xc1b6b677), 0x75dadaaf, 0x63212142, 0x30101020, 0x1affffe5, 0x0ef3f3fd, 0x6dd2d2bf, 0x4ccdcd81, 0x140c0c18, 0x35131326, 0x2fececc3, unchecked((int)0xe15f5fbe), unchecked((int)0xa2979735), unchecked((int)0xcc444488), 0x3917172e, 0x57c4c493, unchecked((int)0xf2a7a755), unchecked((int)0x827e7efc), 0x473d3d7a, unchecked((int)0xac6464c8), unchecked((int)0xe75d5dba), 0x2b191932, unchecked((int)0x957373e6), unchecked((int)0xa06060c0), unchecked((int)0x98818119), unchecked((int)0xd14f4f9e), 0x7fdcdca3, 0x66222244, 0x7e2a2a54, unchecked((int)0xab90903b), unchecked((int)0x8388880b), unchecked((int)0xca46468c), 0x29eeeec7, unchecked((int)0xd3b8b86b), 0x3c141428, 0x79dedea7, unchecked((int)0xe25e5ebc), 0x1d0b0b16, 0x76dbdbad, 0x3be0e0db, 0x56323264, 0x4e3a3a74, 0x1e0a0a14, unchecked((int)0xdb494992), 0x0a06060c, 0x6c242448, unchecked((int)0xe45c5cb8), 0x5dc2c29f, 0x6ed3d3bd, unchecked((int)0xefacac43), unchecked((int)0xa66262c4), unchecked((int)0xa8919139), unchecked((int)0xa4959531), 0x37e4e4d3, unchecked((int)0x8b7979f2), 0x32e7e7d5, 0x43c8c88b, 0x5937376e, unchecked((int)0xb76d6dda), unchecked((int)0x8c8d8d01), 0x64d5d5b1, unchecked((int)0xd24e4e9c), unchecked((int)0xe0a9a949), unchecked((int)0xb46c6cd8), unchecked((int)0xfa5656ac), 0x07f4f4f3, 0x25eaeacf, unchecked((int)0xaf6565ca), unchecked((int)0x8e7a7af4), unchecked((int)0xe9aeae47), 0x18080810, unchecked((int)0xd5baba6f), unchecked((int)0x887878f0), 0x6f25254a, 0x722e2e5c, 0x241c1c38, unchecked((int)0xf1a6a657), unchecked((int)0xc7b4b473), 0x51c6c697, 0x23e8e8cb, 0x7cdddda1, unchecked((int)0x9c7474e8), 0x211f1f3e, unchecked((int)0xdd4b4b96), unchecked((int)0xdcbdbd61), unchecked((int)0x868b8b0d), unchecked((int)0x858a8a0f), unchecked((int)0x907070e0), 0x423e3e7c, unchecked((int)0xc4b5b571), unchecked((int)0xaa6666cc), unchecked((int)0xd8484890), 0x05030306, 0x01f6f6f7, 0x120e0e1c, unchecked((int)0xa36161c2), 0x5f35356a, unchecked((int)0xf95757ae), unchecked((int)0xd0b9b969), unchecked((int)0x91868617), 0x58c1c199, 0x271d1d3a, unchecked((int)0xb99e9e27), 0x38e1e1d9, 0x13f8f8eb, unchecked((int)0xb398982b), 0x33111122, unchecked((int)0xbb6969d2), 0x70d9d9a9, unchecked((int)0x898e8e07), unchecked((int)0xa7949433), unchecked((int)0xb69b9b2d), 0x221e1e3c, unchecked((int)0x92878715), 0x20e9e9c9, 0x49cece87, unchecked((int)0xff5555aa), 0x78282850, 0x7adfdfa5, unchecked((int)0x8f8c8c03), unchecked((int)0xf8a1a159), unchecked((int)0x80898909), 0x170d0d1a, unchecked((int)0xdabfbf65), 0x31e6e6d7, unchecked((int)0xc6424284), unchecked((int)0xb86868d0), unchecked((int)0xc3414182), unchecked((int)0xb0999929), 0x772d2d5a, 0x110f0f1e, unchecked((int)0xcbb0b07b), unchecked((int)0xfc5454a8), unchecked((int)0xd6bbbb6d), 0x3a16162c};

	private static readonly int[] Tinv0 = new int[] {0x50a7f451, 0x5365417e, unchecked((int)0xc3a4171a), unchecked((int)0x965e273a), unchecked((int)0xcb6bab3b), unchecked((int)0xf1459d1f), unchecked((int)0xab58faac), unchecked((int)0x9303e34b), 0x55fa3020, unchecked((int)0xf66d76ad), unchecked((int)0x9176cc88), 0x254c02f5, unchecked((int)0xfcd7e54f), unchecked((int)0xd7cb2ac5), unchecked((int)0x80443526), unchecked((int)0x8fa362b5), 0x495ab1de, 0x671bba25, unchecked((int)0x980eea45), unchecked((int)0xe1c0fe5d), 0x02752fc3, 0x12f04c81, unchecked((int)0xa397468d), unchecked((int)0xc6f9d36b), unchecked((int)0xe75f8f03), unchecked((int)0x959c9215), unchecked((int)0xeb7a6dbf), unchecked((int)0xda595295), 0x2d83bed4, unchecked((int)0xd3217458), 0x2969e049, 0x44c8c98e, 0x6a89c275, 0x78798ef4, 0x6b3e5899, unchecked((int)0xdd71b927), unchecked((int)0xb64fe1be), 0x17ad88f0, 0x66ac20c9, unchecked((int)0xb43ace7d), 0x184adf63, unchecked((int)0x82311ae5), 0x60335197, 0x457f5362, unchecked((int)0xe07764b1), unchecked((int)0x84ae6bbb), 0x1ca081fe, unchecked((int)0x942b08f9), 0x58684870, 0x19fd458f, unchecked((int)0x876cde94), unchecked((int)0xb7f87b52), 0x23d373ab, unchecked((int)0xe2024b72), 0x578f1fe3, 0x2aab5566, 0x0728ebb2, 0x03c2b52f, unchecked((int)0x9a7bc586), unchecked((int)0xa50837d3), unchecked((int)0xf2872830), unchecked((int)0xb2a5bf23), unchecked((int)0xba6a0302), 0x5c8216ed, 0x2b1ccf8a, unchecked((int)0x92b479a7), unchecked((int)0xf0f207f3), unchecked((int)0xa1e2694e), unchecked((int)0xcdf4da65), unchecked((int)0xd5be0506), 0x1f6234d1, unchecked((int)0x8afea6c4), unchecked((int)0x9d532e34), unchecked((int)0xa055f3a2), 0x32e18a05, 0x75ebf6a4, 0x39ec830b, unchecked((int)0xaaef6040), 0x069f715e, 0x51106ebd, unchecked((int)0xf98a213e), 0x3d06dd96, unchecked((int)0xae053edd), 0x46bde64d, unchecked((int)0xb58d5491), 0x055dc471, 0x6fd40604, unchecked((int)0xff155060), 0x24fb9819, unchecked((int)0x97e9bdd6), unchecked((int)0xcc434089), 0x779ed967, unchecked((int)0xbd42e8b0), unchecked((int)0x888b8907), 0x385b19e7, unchecked((int)0xdbeec879), 0x470a7ca1, unchecked((int)0xe90f427c), unchecked((int)0xc91e84f8), 0x00000000, unchecked((int)0x83868009), 0x48ed2b32, unchecked((int)0xac70111e), 0x4e725a6c, unchecked((int)0xfbff0efd), 0x5638850f, 0x1ed5ae3d, 0x27392d36, 0x64d90f0a, 0x21a65c68, unchecked((int)0xd1545b9b), 0x3a2e3624, unchecked((int)0xb1670a0c), 0x0fe75793, unchecked((int)0xd296eeb4), unchecked((int)0x9e919b1b), 0x4fc5c080, unchecked((int)0xa220dc61), 0x694b775a, 0x161a121c, 0x0aba93e2, unchecked((int)0xe52aa0c0), 0x43e0223c, 0x1d171b12, 0x0b0d090e, unchecked((int)0xadc78bf2), unchecked((int)0xb9a8b62d), unchecked((int)0xc8a91e14), unchecked((int)0x8519f157), 0x4c0775af, unchecked((int)0xbbdd99ee), unchecked((int)0xfd607fa3), unchecked((int)0x9f2601f7), unchecked((int)0xbcf5725c), unchecked((int)0xc53b6644), 0x347efb5b, 0x7629438b, unchecked((int)0xdcc623cb), 0x68fcedb6, 0x63f1e4b8, unchecked((int)0xcadc31d7), 0x10856342, 0x40229713, 0x2011c684, 0x7d244a85, unchecked((int)0xf83dbbd2), 0x1132f9ae, 0x6da129c7, 0x4b2f9e1d, unchecked((int)0xf330b2dc), unchecked((int)0xec52860d), unchecked((int)0xd0e3c177), 0x6c16b32b, unchecked((int)0x99b970a9), unchecked((int)0xfa489411), 0x2264e947, unchecked((int)0xc48cfca8), 0x1a3ff0a0, unchecked((int)0xd82c7d56), unchecked((int)0xef903322), unchecked((int)0xc74e4987), unchecked((int)0xc1d138d9), unchecked((int)0xfea2ca8c), 0x360bd498, unchecked((int)0xcf81f5a6), 0x28de7aa5, 0x268eb7da, unchecked((int)0xa4bfad3f), unchecked((int)0xe49d3a2c), 0x0d927850, unchecked((int)0x9bcc5f6a), 0x62467e54, unchecked((int)0xc2138df6), unchecked((int)0xe8b8d890), 0x5ef7392e, unchecked((int)0xf5afc382), unchecked((int)0xbe805d9f), 0x7c93d069, unchecked((int)0xa92dd56f), unchecked((int)0xb31225cf), 0x3b99acc8, unchecked((int)0xa77d1810), 0x6e639ce8, 0x7bbb3bdb, 0x097826cd, unchecked((int)0xf418596e), 0x01b79aec, unchecked((int)0xa89a4f83), 0x656e95e6, 0x7ee6ffaa, 0x08cfbc21, unchecked((int)0xe6e815ef), unchecked((int)0xd99be7ba), unchecked((int)0xce366f4a), unchecked((int)0xd4099fea), unchecked((int)0xd67cb029), unchecked((int)0xafb2a431), 0x31233f2a, 0x3094a5c6, unchecked((int)0xc066a235), 0x37bc4e74, unchecked((int)0xa6ca82fc), unchecked((int)0xb0d090e0), 0x15d8a733, 0x4a9804f1, unchecked((int)0xf7daec41), 0x0e50cd7f, 0x2ff69117, unchecked((int)0x8dd64d76), 0x4db0ef43, 0x544daacc, unchecked((int)0xdf0496e4), unchecked((int)0xe3b5d19e), 0x1b886a4c, unchecked((int)0xb81f2cc1), 0x7f516546, 0x04ea5e9d, 0x5d358c01, 0x737487fa, 0x2e410bfb, 0x5a1d67b3, 0x52d2db92, 0x335610e9, 0x1347d66d, unchecked((int)0x8c61d79a), 0x7a0ca137, unchecked((int)0x8e14f859), unchecked((int)0x893c13eb), unchecked((int)0xee27a9ce), 0x35c961b7, unchecked((int)0xede51ce1), 0x3cb1477a, 0x59dfd29c, 0x3f73f255, 0x79ce1418, unchecked((int)0xbf37c773), unchecked((int)0xeacdf753), 0x5baafd5f, 0x146f3ddf, unchecked((int)0x86db4478), unchecked((int)0x81f3afca), 0x3ec468b9, 0x2c342438, 0x5f40a3c2, 0x72c31d16, 0x0c25e2bc, unchecked((int)0x8b493c28), 0x41950dff, 0x7101a839, unchecked((int)0xdeb30c08), unchecked((int)0x9ce4b4d8), unchecked((int)0x90c15664), 0x6184cb7b, 0x70b632d5, 0x745c6c48, 0x4257b8d0};

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
			return (S[x & 255] & 255 | ((S[(x >> 8) & 255] & 255) << 8) | ((S[(x>>16) & 255] & 255) << 16) | S[(x>>24) & 255] << 24);
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

		private byte[] s;

		private const int BLOCK_SIZE = 16;

		/// <summary>
		/// default constructor - 128 bit block size.
		/// </summary>
		public AESEngine()
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
				if (forEncryption)
				{
					s = Arrays.clone(S);
				}
				else
				{
					s = Arrays.clone(Si);
				}
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

			if (forEncryption)
			{
				unpackBlock(@in, inOff);
				encryptBlock(WorkingKey);
				packBlock(@out, outOff);
			}
			else
			{
				unpackBlock(@in, inOff);
				decryptBlock(WorkingKey);
				packBlock(@out, outOff);
			}

			return BLOCK_SIZE;
		}

		public virtual void reset()
		{
		}

		private void unpackBlock(byte[] bytes, int off)
		{
			int index = off;

			C0 = (bytes[index++] & 0xff);
			C0 |= (bytes[index++] & 0xff) << 8;
			C0 |= (bytes[index++] & 0xff) << 16;
			C0 |= bytes[index++] << 24;

			C1 = (bytes[index++] & 0xff);
			C1 |= (bytes[index++] & 0xff) << 8;
			C1 |= (bytes[index++] & 0xff) << 16;
			C1 |= bytes[index++] << 24;

			C2 = (bytes[index++] & 0xff);
			C2 |= (bytes[index++] & 0xff) << 8;
			C2 |= (bytes[index++] & 0xff) << 16;
			C2 |= bytes[index++] << 24;

			C3 = (bytes[index++] & 0xff);
			C3 |= (bytes[index++] & 0xff) << 8;
			C3 |= (bytes[index++] & 0xff) << 16;
			C3 |= bytes[index++] << 24;
		}

		private void packBlock(byte[] bytes, int off)
		{
			int index = off;

			bytes[index++] = (byte)C0;
			bytes[index++] = (byte)(C0 >> 8);
			bytes[index++] = (byte)(C0 >> 16);
			bytes[index++] = (byte)(C0 >> 24);

			bytes[index++] = (byte)C1;
			bytes[index++] = (byte)(C1 >> 8);
			bytes[index++] = (byte)(C1 >> 16);
			bytes[index++] = (byte)(C1 >> 24);

			bytes[index++] = (byte)C2;
			bytes[index++] = (byte)(C2 >> 8);
			bytes[index++] = (byte)(C2 >> 16);
			bytes[index++] = (byte)(C2 >> 24);

			bytes[index++] = (byte)C3;
			bytes[index++] = (byte)(C3 >> 8);
			bytes[index++] = (byte)(C3 >> 16);
			bytes[index++] = (byte)(C3 >> 24);
		}


		private void encryptBlock(int[][] KW)
		{
			int t0 = this.C0 ^ KW[0][0];
			int t1 = this.C1 ^ KW[0][1];
			int t2 = this.C2 ^ KW[0][2];

			int r = 1, r0, r1, r2, r3 = this.C3 ^ KW[0][3];
			while (r < ROUNDS - 1)
			{
				r0 = T0[t0 & 255] ^ shift(T0[(t1 >> 8) & 255], 24) ^ shift(T0[(t2 >> 16) & 255], 16) ^ shift(T0[(r3 >> 24) & 255], 8) ^ KW[r][0];
				r1 = T0[t1 & 255] ^ shift(T0[(t2 >> 8) & 255], 24) ^ shift(T0[(r3 >> 16) & 255], 16) ^ shift(T0[(t0 >> 24) & 255], 8) ^ KW[r][1];
				r2 = T0[t2 & 255] ^ shift(T0[(r3 >> 8) & 255], 24) ^ shift(T0[(t0 >> 16) & 255], 16) ^ shift(T0[(t1 >> 24) & 255], 8) ^ KW[r][2];
				r3 = T0[r3 & 255] ^ shift(T0[(t0 >> 8) & 255], 24) ^ shift(T0[(t1 >> 16) & 255], 16) ^ shift(T0[(t2 >> 24) & 255], 8) ^ KW[r++][3];
				t0 = T0[r0 & 255] ^ shift(T0[(r1 >> 8) & 255], 24) ^ shift(T0[(r2 >> 16) & 255], 16) ^ shift(T0[(r3 >> 24) & 255], 8) ^ KW[r][0];
				t1 = T0[r1 & 255] ^ shift(T0[(r2 >> 8) & 255], 24) ^ shift(T0[(r3 >> 16) & 255], 16) ^ shift(T0[(r0 >> 24) & 255], 8) ^ KW[r][1];
				t2 = T0[r2 & 255] ^ shift(T0[(r3 >> 8) & 255], 24) ^ shift(T0[(r0 >> 16) & 255], 16) ^ shift(T0[(r1 >> 24) & 255], 8) ^ KW[r][2];
				r3 = T0[r3 & 255] ^ shift(T0[(r0 >> 8) & 255], 24) ^ shift(T0[(r1 >> 16) & 255], 16) ^ shift(T0[(r2 >> 24) & 255], 8) ^ KW[r++][3];
			}

			r0 = T0[t0 & 255] ^ shift(T0[(t1 >> 8) & 255], 24) ^ shift(T0[(t2 >> 16) & 255], 16) ^ shift(T0[(r3 >> 24) & 255], 8) ^ KW[r][0];
			r1 = T0[t1 & 255] ^ shift(T0[(t2 >> 8) & 255], 24) ^ shift(T0[(r3 >> 16) & 255], 16) ^ shift(T0[(t0 >> 24) & 255], 8) ^ KW[r][1];
			r2 = T0[t2 & 255] ^ shift(T0[(r3 >> 8) & 255], 24) ^ shift(T0[(t0 >> 16) & 255], 16) ^ shift(T0[(t1 >> 24) & 255], 8) ^ KW[r][2];
			r3 = T0[r3 & 255] ^ shift(T0[(t0 >> 8) & 255], 24) ^ shift(T0[(t1 >> 16) & 255], 16) ^ shift(T0[(t2 >> 24) & 255], 8) ^ KW[r++][3];

			// the final round's table is a simple function of S so we don't use a whole other four tables for it

			this.C0 = (S[r0 & 255] & 255) ^ ((S[(r1 >> 8) & 255] & 255) << 8) ^ ((s[(r2>>16) & 255] & 255) << 16) ^ (s[(r3>>24) & 255] << 24) ^ KW[r][0];
			this.C1 = (s[r1 & 255] & 255) ^ ((S[(r2 >> 8) & 255] & 255) << 8) ^ ((S[(r3>>16) & 255] & 255) << 16) ^ (s[(r0>>24) & 255] << 24) ^ KW[r][1];
			this.C2 = (s[r2 & 255] & 255) ^ ((S[(r3 >> 8) & 255] & 255) << 8) ^ ((S[(r0>>16) & 255] & 255) << 16) ^ (S[(r1>>24) & 255] << 24) ^ KW[r][2];
			this.C3 = (s[r3 & 255] & 255) ^ ((s[(r0 >> 8) & 255] & 255) << 8) ^ ((s[(r1>>16) & 255] & 255) << 16) ^ (S[(r2>>24) & 255] << 24) ^ KW[r][3];
		}

		private void decryptBlock(int[][] KW)
		{
			int t0 = this.C0 ^ KW[ROUNDS][0];
			int t1 = this.C1 ^ KW[ROUNDS][1];
			int t2 = this.C2 ^ KW[ROUNDS][2];

			int r = ROUNDS - 1, r0, r1, r2, r3 = this.C3 ^ KW[ROUNDS][3];
			while (r > 1)
			{
				r0 = Tinv0[t0 & 255] ^ shift(Tinv0[(r3 >> 8) & 255], 24) ^ shift(Tinv0[(t2 >> 16) & 255], 16) ^ shift(Tinv0[(t1 >> 24) & 255], 8) ^ KW[r][0];
				r1 = Tinv0[t1 & 255] ^ shift(Tinv0[(t0 >> 8) & 255], 24) ^ shift(Tinv0[(r3 >> 16) & 255], 16) ^ shift(Tinv0[(t2 >> 24) & 255], 8) ^ KW[r][1];
				r2 = Tinv0[t2 & 255] ^ shift(Tinv0[(t1 >> 8) & 255], 24) ^ shift(Tinv0[(t0 >> 16) & 255], 16) ^ shift(Tinv0[(r3 >> 24) & 255], 8) ^ KW[r][2];
				r3 = Tinv0[r3 & 255] ^ shift(Tinv0[(t2 >> 8) & 255], 24) ^ shift(Tinv0[(t1 >> 16) & 255], 16) ^ shift(Tinv0[(t0 >> 24) & 255], 8) ^ KW[r--][3];
				t0 = Tinv0[r0 & 255] ^ shift(Tinv0[(r3 >> 8) & 255], 24) ^ shift(Tinv0[(r2 >> 16) & 255], 16) ^ shift(Tinv0[(r1 >> 24) & 255], 8) ^ KW[r][0];
				t1 = Tinv0[r1 & 255] ^ shift(Tinv0[(r0 >> 8) & 255], 24) ^ shift(Tinv0[(r3 >> 16) & 255], 16) ^ shift(Tinv0[(r2 >> 24) & 255], 8) ^ KW[r][1];
				t2 = Tinv0[r2 & 255] ^ shift(Tinv0[(r1 >> 8) & 255], 24) ^ shift(Tinv0[(r0 >> 16) & 255], 16) ^ shift(Tinv0[(r3 >> 24) & 255], 8) ^ KW[r][2];
				r3 = Tinv0[r3 & 255] ^ shift(Tinv0[(r2 >> 8) & 255], 24) ^ shift(Tinv0[(r1 >> 16) & 255], 16) ^ shift(Tinv0[(r0 >> 24) & 255], 8) ^ KW[r--][3];
			}

			r0 = Tinv0[t0 & 255] ^ shift(Tinv0[(r3 >> 8) & 255], 24) ^ shift(Tinv0[(t2 >> 16) & 255], 16) ^ shift(Tinv0[(t1 >> 24) & 255], 8) ^ KW[r][0];
			r1 = Tinv0[t1 & 255] ^ shift(Tinv0[(t0 >> 8) & 255], 24) ^ shift(Tinv0[(r3 >> 16) & 255], 16) ^ shift(Tinv0[(t2 >> 24) & 255], 8) ^ KW[r][1];
			r2 = Tinv0[t2 & 255] ^ shift(Tinv0[(t1 >> 8) & 255], 24) ^ shift(Tinv0[(t0 >> 16) & 255], 16) ^ shift(Tinv0[(r3 >> 24) & 255], 8) ^ KW[r][2];
			r3 = Tinv0[r3 & 255] ^ shift(Tinv0[(t2 >> 8) & 255], 24) ^ shift(Tinv0[(t1 >> 16) & 255], 16) ^ shift(Tinv0[(t0 >> 24) & 255], 8) ^ KW[r][3];

			// the final round's table is a simple function of Si so we don't use a whole other four tables for it

			this.C0 = (Si[r0 & 255] & 255) ^ ((s[(r3 >> 8) & 255] & 255) << 8) ^ ((s[(r2>>16) & 255] & 255) << 16) ^ (Si[(r1>>24) & 255] << 24) ^ KW[0][0];
			this.C1 = (s[r1 & 255] & 255) ^ ((s[(r0 >> 8) & 255] & 255) << 8) ^ ((Si[(r3>>16) & 255] & 255) << 16) ^ (s[(r2>>24) & 255] << 24) ^ KW[0][1];
			this.C2 = (s[r2 & 255] & 255) ^ ((Si[(r1 >> 8) & 255] & 255) << 8) ^ ((Si[(r0>>16) & 255] & 255) << 16) ^ (s[(r3>>24) & 255] << 24) ^ KW[0][2];
			this.C3 = (Si[r3 & 255] & 255) ^ ((s[(r2 >> 8) & 255] & 255) << 8) ^ ((s[(r1>>16) & 255] & 255) << 16) ^ (s[(r0>>24) & 255] << 24) ^ KW[0][3];
		}
	}

}