using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;

	/// <summary>
	/// an implementation of Rijndael, based on the documentation and reference implementation
	/// by Paulo Barreto, Vincent Rijmen, for v2.0 August '99.
	/// <para>
	/// Note: this implementation is based on information prior to final NIST publication.
	/// </para>
	/// </summary>
	public class RijndaelEngine : BlockCipher
	{
		private const int MAXROUNDS = 14;

		private const int MAXKC = (256 / 4);

		private static readonly byte[] logtable = new byte[] {0, 0, 25, 1, 50, 2, 26, unchecked(198), 75, unchecked(199), 27, 104, 51, unchecked(238), unchecked(223), 3, 100, 4, unchecked(224), 14, 52, unchecked(141), unchecked(129), unchecked(239), 76, 113, 8, unchecked(200), unchecked(248), 105, 28, unchecked(193), 125, unchecked(194), 29, unchecked(181), unchecked(249), unchecked(185), 39, 106, 77, unchecked(228), unchecked(166), 114, unchecked(154), unchecked(201), 9, 120, 101, 47, unchecked(138), 5, 33, 15, unchecked(225), 36, 18, unchecked(240), unchecked(130), 69, 53, unchecked(147), unchecked(218), unchecked(142), unchecked(150), unchecked(143), unchecked(219), unchecked(189), 54, unchecked(208), unchecked(206), unchecked(148), 19, 92, unchecked(210), unchecked(241), 64, 70, unchecked(131), 56, 102, unchecked(221), unchecked(253), 48, unchecked(191), 6, unchecked(139), 98, unchecked(179), 37, unchecked(226), unchecked(152), 34, unchecked(136), unchecked(145), 16, 126, 110, 72, unchecked(195), unchecked(163), unchecked(182), 30, 66, 58, 107, 40, 84, unchecked(250), unchecked(133), 61, unchecked(186), 43, 121, 10, 21, unchecked(155), unchecked(159), 94, unchecked(202), 78, unchecked(212), unchecked(172), unchecked(229), unchecked(243), 115, unchecked(167), 87, unchecked(175), 88, unchecked(168), 80, unchecked(244), unchecked(234), unchecked(214), 116, 79, unchecked(174), unchecked(233), unchecked(213), unchecked(231), unchecked(230), unchecked(173), unchecked(232), 44, unchecked(215), 117, 122, unchecked(235), 22, 11, unchecked(245), 89, unchecked(203), 95, unchecked(176), unchecked(156), unchecked(169), 81, unchecked(160), 127, 12, unchecked(246), 111, 23, unchecked(196), 73, unchecked(236), unchecked(216), 67, 31, 45, unchecked(164), 118, 123, unchecked(183), unchecked(204), unchecked(187), 62, 90, unchecked(251), 96, unchecked(177), unchecked(134), 59, 82, unchecked(161), 108, unchecked(170), 85, 41, unchecked(157), unchecked(151), unchecked(178), unchecked(135), unchecked(144), 97, unchecked(190), unchecked(220), unchecked(252), unchecked(188), unchecked(149), unchecked(207), unchecked(205), 55, 63, 91, unchecked(209), 83, 57, unchecked(132), 60, 65, unchecked(162), 109, 71, 20, 42, unchecked(158), 93, 86, unchecked(242), unchecked(211), unchecked(171), 68, 17, unchecked(146), unchecked(217), 35, 32, 46, unchecked(137), unchecked(180), 124, unchecked(184), 38, 119, unchecked(153), unchecked(227), unchecked(165), 103, 74, unchecked(237), unchecked(222), unchecked(197), 49, unchecked(254), 24, 13, 99, unchecked(140), unchecked(128), unchecked(192), unchecked(247), 112, 7};

		private static readonly byte[] aLogtable = new byte[] {0, 3, 5, 15, 17, 51, 85, unchecked(255), 26, 46, 114, unchecked(150), unchecked(161), unchecked(248), 19, 53, 95, unchecked(225), 56, 72, unchecked(216), 115, unchecked(149), unchecked(164), unchecked(247), 2, 6, 10, 30, 34, 102, unchecked(170), unchecked(229), 52, 92, unchecked(228), 55, 89, unchecked(235), 38, 106, unchecked(190), unchecked(217), 112, unchecked(144), unchecked(171), unchecked(230), 49, 83, unchecked(245), 4, 12, 20, 60, 68, unchecked(204), 79, unchecked(209), 104, unchecked(184), unchecked(211), 110, unchecked(178), unchecked(205), 76, unchecked(212), 103, unchecked(169), unchecked(224), 59, 77, unchecked(215), 98, unchecked(166), unchecked(241), 8, 24, 40, 120, unchecked(136), unchecked(131), unchecked(158), unchecked(185), unchecked(208), 107, unchecked(189), unchecked(220), 127, unchecked(129), unchecked(152), unchecked(179), unchecked(206), 73, unchecked(219), 118, unchecked(154), unchecked(181), unchecked(196), 87, unchecked(249), 16, 48, 80, unchecked(240), 11, 29, 39, 105, unchecked(187), unchecked(214), 97, unchecked(163), unchecked(254), 25, 43, 125, unchecked(135), unchecked(146), unchecked(173), unchecked(236), 47, 113, unchecked(147), unchecked(174), unchecked(233), 32, 96, unchecked(160), unchecked(251), 22, 58, 78, unchecked(210), 109, unchecked(183), unchecked(194), 93, unchecked(231), 50, 86, unchecked(250), 21, 63, 65, unchecked(195), 94, unchecked(226), 61, 71, unchecked(201), 64, unchecked(192), 91, unchecked(237), 44, 116, unchecked(156), unchecked(191), unchecked(218), 117, unchecked(159), unchecked(186), unchecked(213), 100, unchecked(172), unchecked(239), 42, 126, unchecked(130), unchecked(157), unchecked(188), unchecked(223), 122, unchecked(142), unchecked(137), unchecked(128), unchecked(155), unchecked(182), unchecked(193), 88, unchecked(232), 35, 101, unchecked(175), unchecked(234), 37, 111, unchecked(177), unchecked(200), 67, unchecked(197), 84, unchecked(252), 31, 33, 99, unchecked(165), unchecked(244), 7, 9, 27, 45, 119, unchecked(153), unchecked(176), unchecked(203), 70, unchecked(202), 69, unchecked(207), 74, unchecked(222), 121, unchecked(139), unchecked(134), unchecked(145), unchecked(168), unchecked(227), 62, 66, unchecked(198), 81, unchecked(243), 14, 18, 54, 90, unchecked(238), 41, 123, unchecked(141), unchecked(140), unchecked(143), unchecked(138), unchecked(133), unchecked(148), unchecked(167), unchecked(242), 13, 23, 57, 75, unchecked(221), 124, unchecked(132), unchecked(151), unchecked(162), unchecked(253), 28, 36, 108, unchecked(180), unchecked(199), 82, unchecked(246), 1, 3, 5, 15, 17, 51, 85, unchecked(255), 26, 46, 114, unchecked(150), unchecked(161), unchecked(248), 19, 53, 95, unchecked(225), 56, 72, unchecked(216), 115, unchecked(149), unchecked(164), unchecked(247), 2, 6, 10, 30, 34, 102, unchecked(170), unchecked(229), 52, 92, unchecked(228), 55, 89, unchecked(235), 38, 106, unchecked(190), unchecked(217), 112, unchecked(144), unchecked(171), unchecked(230), 49, 83, unchecked(245), 4, 12, 20, 60, 68, unchecked(204), 79, unchecked(209), 104, unchecked(184), unchecked(211), 110, unchecked(178), unchecked(205), 76, unchecked(212), 103, unchecked(169), unchecked(224), 59, 77, unchecked(215), 98, unchecked(166), unchecked(241), 8, 24, 40, 120, unchecked(136), unchecked(131), unchecked(158), unchecked(185), unchecked(208), 107, unchecked(189), unchecked(220), 127, unchecked(129), unchecked(152), unchecked(179), unchecked(206), 73, unchecked(219), 118, unchecked(154), unchecked(181), unchecked(196), 87, unchecked(249), 16, 48, 80, unchecked(240), 11, 29, 39, 105, unchecked(187), unchecked(214), 97, unchecked(163), unchecked(254), 25, 43, 125, unchecked(135), unchecked(146), unchecked(173), unchecked(236), 47, 113, unchecked(147), unchecked(174), unchecked(233), 32, 96, unchecked(160), unchecked(251), 22, 58, 78, unchecked(210), 109, unchecked(183), unchecked(194), 93, unchecked(231), 50, 86, unchecked(250), 21, 63, 65, unchecked(195), 94, unchecked(226), 61, 71, unchecked(201), 64, unchecked(192), 91, unchecked(237), 44, 116, unchecked(156), unchecked(191), unchecked(218), 117, unchecked(159), unchecked(186), unchecked(213), 100, unchecked(172), unchecked(239), 42, 126, unchecked(130), unchecked(157), unchecked(188), unchecked(223), 122, unchecked(142), unchecked(137), unchecked(128), unchecked(155), unchecked(182), unchecked(193), 88, unchecked(232), 35, 101, unchecked(175), unchecked(234), 37, 111, unchecked(177), unchecked(200), 67, unchecked(197), 84, unchecked(252), 31, 33, 99, unchecked(165), unchecked(244), 7, 9, 27, 45, 119, unchecked(153), unchecked(176), unchecked(203), 70, unchecked(202), 69, unchecked(207), 74, unchecked(222), 121, unchecked(139), unchecked(134), unchecked(145), unchecked(168), unchecked(227), 62, 66, unchecked(198), 81, unchecked(243), 14, 18, 54, 90, unchecked(238), 41, 123, unchecked(141), unchecked(140), unchecked(143), unchecked(138), unchecked(133), unchecked(148), unchecked(167), unchecked(242), 13, 23, 57, 75, unchecked(221), 124, unchecked(132), unchecked(151), unchecked(162), unchecked(253), 28, 36, 108, unchecked(180), unchecked(199), 82, unchecked(246), 1};

		private static readonly byte[] S = new byte[] {99, 124, 119, 123, unchecked(242), 107, 111, unchecked(197), 48, 1, 103, 43, unchecked(254), unchecked(215), unchecked(171), 118, unchecked(202), unchecked(130), unchecked(201), 125, unchecked(250), 89, 71, unchecked(240), unchecked(173), unchecked(212), unchecked(162), unchecked(175), unchecked(156), unchecked(164), 114, unchecked(192), unchecked(183), unchecked(253), unchecked(147), 38, 54, 63, unchecked(247), unchecked(204), 52, unchecked(165), unchecked(229), unchecked(241), 113, unchecked(216), 49, 21, 4, unchecked(199), 35, unchecked(195), 24, unchecked(150), 5, unchecked(154), 7, 18, unchecked(128), unchecked(226), unchecked(235), 39, unchecked(178), 117, 9, unchecked(131), 44, 26, 27, 110, 90, unchecked(160), 82, 59, unchecked(214), unchecked(179), 41, unchecked(227), 47, unchecked(132), 83, unchecked(209), 0, unchecked(237), 32, unchecked(252), unchecked(177), 91, 106, unchecked(203), unchecked(190), 57, 74, 76, 88, unchecked(207), unchecked(208), unchecked(239), unchecked(170), unchecked(251), 67, 77, 51, unchecked(133), 69, unchecked(249), 2, 127, 80, 60, unchecked(159), unchecked(168), 81, unchecked(163), 64, unchecked(143), unchecked(146), unchecked(157), 56, unchecked(245), unchecked(188), unchecked(182), unchecked(218), 33, 16, unchecked(255), unchecked(243), unchecked(210), unchecked(205), 12, 19, unchecked(236), 95, unchecked(151), 68, 23, unchecked(196), unchecked(167), 126, 61, 100, 93, 25, 115, 96, unchecked(129), 79, unchecked(220), 34, 42, unchecked(144), unchecked(136), 70, unchecked(238), unchecked(184), 20, unchecked(222), 94, 11, unchecked(219), unchecked(224), 50, 58, 10, 73, 6, 36, 92, unchecked(194), unchecked(211), unchecked(172), 98, unchecked(145), unchecked(149), unchecked(228), 121, unchecked(231), unchecked(200), 55, 109, unchecked(141), unchecked(213), 78, unchecked(169), 108, 86, unchecked(244), unchecked(234), 101, 122, unchecked(174), 8, unchecked(186), 120, 37, 46, 28, unchecked(166), unchecked(180), unchecked(198), unchecked(232), unchecked(221), 116, 31, 75, unchecked(189), unchecked(139), unchecked(138), 112, 62, unchecked(181), 102, 72, 3, unchecked(246), 14, 97, 53, 87, unchecked(185), unchecked(134), unchecked(193), 29, unchecked(158), unchecked(225), unchecked(248), unchecked(152), 17, 105, unchecked(217), unchecked(142), unchecked(148), unchecked(155), 30, unchecked(135), unchecked(233), unchecked(206), 85, 40, unchecked(223), unchecked(140), unchecked(161), unchecked(137), 13, unchecked(191), unchecked(230), 66, 104, 65, unchecked(153), 45, 15, unchecked(176), 84, unchecked(187), 22};

		private static readonly byte[] Si = new byte[] {82, 9, 106, unchecked(213), 48, 54, unchecked(165), 56, unchecked(191), 64, unchecked(163), unchecked(158), unchecked(129), unchecked(243), unchecked(215), unchecked(251), 124, unchecked(227), 57, unchecked(130), unchecked(155), 47, unchecked(255), unchecked(135), 52, unchecked(142), 67, 68, unchecked(196), unchecked(222), unchecked(233), unchecked(203), 84, 123, unchecked(148), 50, unchecked(166), unchecked(194), 35, 61, unchecked(238), 76, unchecked(149), 11, 66, unchecked(250), unchecked(195), 78, 8, 46, unchecked(161), 102, 40, unchecked(217), 36, unchecked(178), 118, 91, unchecked(162), 73, 109, unchecked(139), unchecked(209), 37, 114, unchecked(248), unchecked(246), 100, unchecked(134), 104, unchecked(152), 22, unchecked(212), unchecked(164), 92, unchecked(204), 93, 101, unchecked(182), unchecked(146), 108, 112, 72, 80, unchecked(253), unchecked(237), unchecked(185), unchecked(218), 94, 21, 70, 87, unchecked(167), unchecked(141), unchecked(157), unchecked(132), unchecked(144), unchecked(216), unchecked(171), 0, unchecked(140), unchecked(188), unchecked(211), 10, unchecked(247), unchecked(228), 88, 5, unchecked(184), unchecked(179), 69, 6, unchecked(208), 44, 30, unchecked(143), unchecked(202), 63, 15, 2, unchecked(193), unchecked(175), unchecked(189), 3, 1, 19, unchecked(138), 107, 58, unchecked(145), 17, 65, 79, 103, unchecked(220), unchecked(234), unchecked(151), unchecked(242), unchecked(207), unchecked(206), unchecked(240), unchecked(180), unchecked(230), 115, unchecked(150), unchecked(172), 116, 34, unchecked(231), unchecked(173), 53, unchecked(133), unchecked(226), unchecked(249), 55, unchecked(232), 28, 117, unchecked(223), 110, 71, unchecked(241), 26, 113, 29, 41, unchecked(197), unchecked(137), 111, unchecked(183), 98, 14, unchecked(170), 24, unchecked(190), 27, unchecked(252), 86, 62, 75, unchecked(198), unchecked(210), 121, 32, unchecked(154), unchecked(219), unchecked(192), unchecked(254), 120, unchecked(205), 90, unchecked(244), 31, unchecked(221), unchecked(168), 51, unchecked(136), 7, unchecked(199), 49, unchecked(177), 18, 16, 89, 39, unchecked(128), unchecked(236), 95, 96, 81, 127, unchecked(169), 25, unchecked(181), 74, 13, 45, unchecked(229), 122, unchecked(159), unchecked(147), unchecked(201), unchecked(156), unchecked(239), unchecked(160), unchecked(224), 59, 77, unchecked(174), 42, unchecked(245), unchecked(176), unchecked(200), unchecked(235), unchecked(187), 60, unchecked(131), 83, unchecked(153), 97, 23, 43, 4, 126, unchecked(186), 119, unchecked(214), 38, unchecked(225), 105, 20, 99, 85, 33, 12, 125};

		private static readonly int[] rcon = new int[] {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91};

		internal static byte[][] shifts0 = new byte[][]
		{
			new byte[] {0, 8, 16, 24},
			new byte[] {0, 8, 16, 24},
			new byte[] {0, 8, 16, 24},
			new byte[] {0, 8, 16, 32},
			new byte[] {0, 8, 24, 32}
		};

		internal static byte[][] shifts1 = new byte[][]
		{
			new byte[] {0, 24, 16, 8},
			new byte[] {0, 32, 24, 16},
			new byte[] {0, 40, 32, 24},
			new byte[] {0, 48, 40, 24},
			new byte[] {0, 56, 40, 32}
		};

		/// <summary>
		/// multiply two elements of GF(2^m)
		/// needed for MixColumn and InvMixColumn
		/// </summary>
		private byte mul0x2(int b)
		{
			if (b != 0)
			{
				return aLogtable[25 + (logtable[b] & 0xff)];
			}
			else
			{
				return 0;
			}
		}

		private byte mul0x3(int b)
		{
			if (b != 0)
			{
				return aLogtable[1 + (logtable[b] & 0xff)];
			}
			else
			{
				return 0;
			}
		}

		private byte mul0x9(int b)
		{
			if (b >= 0)
			{
				return aLogtable[199 + b];
			}
			else
			{
				return 0;
			}
		}

		private byte mul0xb(int b)
		{
			if (b >= 0)
			{
				return aLogtable[104 + b];
			}
			else
			{
				return 0;
			}
		}

		private byte mul0xd(int b)
		{
			if (b >= 0)
			{
				return aLogtable[238 + b];
			}
			else
			{
				return 0;
			}
		}

		private byte mul0xe(int b)
		{
			if (b >= 0)
			{
				return aLogtable[223 + b];
			}
			else
			{
				return 0;
			}
		}

		/// <summary>
		/// xor corresponding text input and round key input bytes
		/// </summary>
		private void KeyAddition(long[] rk)
		{
			A0 ^= rk[0];
			A1 ^= rk[1];
			A2 ^= rk[2];
			A3 ^= rk[3];
		}

		private long shift(long r, int shift)
		{
			return ((((long)((ulong)r >> shift)) | (r << (BC - shift)))) & BC_MASK;
		}

		/// <summary>
		/// Row 0 remains unchanged
		/// The other three rows are shifted a variable amount
		/// </summary>
		private void ShiftRow(byte[] shiftsSC)
		{
			A1 = shift(A1, shiftsSC[1]);
			A2 = shift(A2, shiftsSC[2]);
			A3 = shift(A3, shiftsSC[3]);
		}

		private long applyS(long r, byte[] box)
		{
			long res = 0;

			for (int j = 0; j < BC; j += 8)
			{
				res |= (long)(box[(int)((r >> j) & 0xff)] & 0xff) << j;
			}

			return res;
		}

		/// <summary>
		/// Replace every byte of the input by the byte at that place
		/// in the nonlinear S-box
		/// </summary>
		private void Substitution(byte[] box)
		{
			A0 = applyS(A0, box);
			A1 = applyS(A1, box);
			A2 = applyS(A2, box);
			A3 = applyS(A3, box);
		}

		/// <summary>
		/// Mix the bytes of every column in a linear way
		/// </summary>
		private void MixColumn()
		{
			long r0, r1, r2, r3;

			r0 = r1 = r2 = r3 = 0;

			for (int j = 0; j < BC; j += 8)
			{
				int a0 = (int)((A0 >> j) & 0xff);
				int a1 = (int)((A1 >> j) & 0xff);
				int a2 = (int)((A2 >> j) & 0xff);
				int a3 = (int)((A3 >> j) & 0xff);

				r0 |= (long)((mul0x2(a0) ^ mul0x3(a1) ^ a2 ^ a3) & 0xff) << j;

				r1 |= (long)((mul0x2(a1) ^ mul0x3(a2) ^ a3 ^ a0) & 0xff) << j;

				r2 |= (long)((mul0x2(a2) ^ mul0x3(a3) ^ a0 ^ a1) & 0xff) << j;

				r3 |= (long)((mul0x2(a3) ^ mul0x3(a0) ^ a1 ^ a2) & 0xff) << j;
			}

			A0 = r0;
			A1 = r1;
			A2 = r2;
			A3 = r3;
		}

		/// <summary>
		/// Mix the bytes of every column in a linear way
		/// This is the opposite operation of Mixcolumn
		/// </summary>
		private void InvMixColumn()
		{
			long r0, r1, r2, r3;

			r0 = r1 = r2 = r3 = 0;
			for (int j = 0; j < BC; j += 8)
			{
				int a0 = (int)((A0 >> j) & 0xff);
				int a1 = (int)((A1 >> j) & 0xff);
				int a2 = (int)((A2 >> j) & 0xff);
				int a3 = (int)((A3 >> j) & 0xff);

				//
				// pre-lookup the log table
				//
				a0 = (a0 != 0) ? (logtable[a0 & 0xff] & 0xff) : -1;
				a1 = (a1 != 0) ? (logtable[a1 & 0xff] & 0xff) : -1;
				a2 = (a2 != 0) ? (logtable[a2 & 0xff] & 0xff) : -1;
				a3 = (a3 != 0) ? (logtable[a3 & 0xff] & 0xff) : -1;

				r0 |= (long)((mul0xe(a0) ^ mul0xb(a1) ^ mul0xd(a2) ^ mul0x9(a3)) & 0xff) << j;

				r1 |= (long)((mul0xe(a1) ^ mul0xb(a2) ^ mul0xd(a3) ^ mul0x9(a0)) & 0xff) << j;

				r2 |= (long)((mul0xe(a2) ^ mul0xb(a3) ^ mul0xd(a0) ^ mul0x9(a1)) & 0xff) << j;

				r3 |= (long)((mul0xe(a3) ^ mul0xb(a0) ^ mul0xd(a1) ^ mul0x9(a2)) & 0xff) << j;
			}

			A0 = r0;
			A1 = r1;
			A2 = r2;
			A3 = r3;
		}

		/// <summary>
		/// Calculate the necessary round keys
		/// The number of calculations depends on keyBits and blockBits
		/// </summary>
		private long[][] generateWorkingKey(byte[] key)
		{
			int KC;
			int t, rconpointer = 0;
			int keyBits = key.Length * 8;
			byte[][] tk = RectangularArrays.ReturnRectangularSbyteArray(4, MAXKC);
			long[][] W = RectangularArrays.ReturnRectangularLongArray(MAXROUNDS + 1, 4);

			switch (keyBits)
			{
			case 128:
				KC = 4;
				break;
			case 160:
				KC = 5;
				break;
			case 192:
				KC = 6;
				break;
			case 224:
				KC = 7;
				break;
			case 256:
				KC = 8;
				break;
			default :
				throw new IllegalArgumentException("Key length not 128/160/192/224/256 bits.");
			}

			if (keyBits >= blockBits)
			{
				ROUNDS = KC + 6;
			}
			else
			{
				ROUNDS = (BC / 8) + 6;
			}

			//
			// copy the key into the processing area
			//
			int index = 0;

			for (int i = 0; i < key.Length; i++)
			{
				tk[i % 4][i / 4] = key[index++];
			}

			t = 0;

			//
			// copy values into round key array
			//
			for (int j = 0; (j < KC) && (t < (ROUNDS + 1) * (BC / 8)); j++, t++)
			{
				for (int i = 0; i < 4; i++)
				{
					W[t / (BC / 8)][i] |= (long)(tk[i][j] & 0xff) << ((t * 8) % BC);
				}
			}

			//
			// while not enough round key material calculated
			// calculate new values
			//
			while (t < (ROUNDS + 1) * (BC / 8))
			{
				for (int i = 0; i < 4; i++)
				{
					tk[i][0] ^= S[tk[(i + 1) % 4][KC - 1] & 0xff];
				}
				tk[0][0] ^= (byte)rcon[rconpointer++];

				if (KC <= 6)
				{
					for (int j = 1; j < KC; j++)
					{
						for (int i = 0; i < 4; i++)
						{
							tk[i][j] ^= tk[i][j - 1];
						}
					}
				}
				else
				{
					for (int j = 1; j < 4; j++)
					{
						for (int i = 0; i < 4; i++)
						{
							tk[i][j] ^= tk[i][j - 1];
						}
					}
					for (int i = 0; i < 4; i++)
					{
						tk[i][4] ^= S[tk[i][3] & 0xff];
					}
					for (int j = 5; j < KC; j++)
					{
						for (int i = 0; i < 4; i++)
						{
							tk[i][j] ^= tk[i][j - 1];
						}
					}
				}

				//
				// copy values into round key array
				//
				for (int j = 0; (j < KC) && (t < (ROUNDS + 1) * (BC / 8)); j++, t++)
				{
					for (int i = 0; i < 4; i++)
					{
						W[t / (BC / 8)][i] |= (long)(tk[i][j] & 0xff) << ((t * 8) % (BC));
					}
				}
			}

			return W;
		}

		private int BC;
		private long BC_MASK;
		private int ROUNDS;
		private int blockBits;
		private long[][] workingKey;
		private long A0, A1, A2, A3;
		private bool forEncryption;
		private byte[] shifts0SC;
		private byte[] shifts1SC;

		/// <summary>
		/// default constructor - 128 bit block size.
		/// </summary>
		public RijndaelEngine() : this(128)
		{
		}

		/// <summary>
		/// basic constructor - set the cipher up for a given blocksize
		/// </summary>
		/// <param name="blockBits"> the blocksize in bits, must be 128, 192, or 256. </param>
		public RijndaelEngine(int blockBits)
		{
			switch (blockBits)
			{
			case 128:
				BC = 32;
				BC_MASK = 0xffffffffL;
				shifts0SC = shifts0[0];
				shifts1SC = shifts1[0];
				break;
			case 160:
				BC = 40;
				BC_MASK = 0xffffffffffL;
				shifts0SC = shifts0[1];
				shifts1SC = shifts1[1];
				break;
			case 192:
				BC = 48;
				BC_MASK = 0xffffffffffffL;
				shifts0SC = shifts0[2];
				shifts1SC = shifts1[2];
				break;
			case 224:
				BC = 56;
				BC_MASK = 0xffffffffffffffL;
				shifts0SC = shifts0[3];
				shifts1SC = shifts1[3];
				break;
			case 256:
				BC = 64;
				BC_MASK = unchecked((long)0xffffffffffffffffL);
				shifts0SC = shifts0[4];
				shifts1SC = shifts1[4];
				break;
			default:
				throw new IllegalArgumentException("unknown blocksize to Rijndael");
			}

			this.blockBits = blockBits;
		}

		/// <summary>
		/// initialise a Rijndael cipher.
		/// </summary>
		/// <param name="forEncryption"> whether or not we are for encryption. </param>
		/// <param name="params"> the parameters required to set up the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			if (@params is KeyParameter)
			{
				workingKey = generateWorkingKey(((KeyParameter)@params).getKey());
				this.forEncryption = forEncryption;
				return;
			}

			throw new IllegalArgumentException("invalid parameter passed to Rijndael init - " + @params.GetType().getName());
		}

		public virtual string getAlgorithmName()
		{
			return "Rijndael";
		}

		public virtual int getBlockSize()
		{
			return BC / 2;
		}

		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if (workingKey == null)
			{
				throw new IllegalStateException("Rijndael engine not initialised");
			}

			if ((inOff + (BC / 2)) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOff + (BC / 2)) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			if (forEncryption)
			{
				unpackBlock(@in, inOff);
				encryptBlock(workingKey);
				packBlock(@out, outOff);
			}
			else
			{
				unpackBlock(@in, inOff);
				decryptBlock(workingKey);
				packBlock(@out, outOff);
			}

			return BC / 2;
		}

		public virtual void reset()
		{
		}

		private void unpackBlock(byte[] bytes, int off)
		{
			int index = off;

			A0 = (bytes[index++] & 0xff);
			A1 = (bytes[index++] & 0xff);
			A2 = (bytes[index++] & 0xff);
			A3 = (bytes[index++] & 0xff);

			for (int j = 8; j != BC; j += 8)
			{
				A0 |= (long)(bytes[index++] & 0xff) << j;
				A1 |= (long)(bytes[index++] & 0xff) << j;
				A2 |= (long)(bytes[index++] & 0xff) << j;
				A3 |= (long)(bytes[index++] & 0xff) << j;
			}
		}

		private void packBlock(byte[] bytes, int off)
		{
			int index = off;

			for (int j = 0; j != BC; j += 8)
			{
				bytes[index++] = (byte)(A0 >> j);
				bytes[index++] = (byte)(A1 >> j);
				bytes[index++] = (byte)(A2 >> j);
				bytes[index++] = (byte)(A3 >> j);
			}
		}

		private void encryptBlock(long[][] rk)
		{
			int r;

			//
			// begin with a key addition
			//
			KeyAddition(rk[0]);

			//
			// ROUNDS-1 ordinary rounds
			//
			for (r = 1; r < ROUNDS; r++)
			{
				Substitution(S);
				ShiftRow(shifts0SC);
				MixColumn();
				KeyAddition(rk[r]);
			}

			//
			// Last round is special: there is no MixColumn
			//
			Substitution(S);
			ShiftRow(shifts0SC);
			KeyAddition(rk[ROUNDS]);
		}

		private void decryptBlock(long[][] rk)
		{
			int r;

			// To decrypt: apply the inverse operations of the encrypt routine,
			//             in opposite order
			//
			// (KeyAddition is an involution: it 's equal to its inverse)
			// (the inverse of Substitution with table S is Substitution with the inverse table of S)
			// (the inverse of Shiftrow is Shiftrow over a suitable distance)
			//

			// First the special round:
			//   without InvMixColumn
			//   with extra KeyAddition
			//
			KeyAddition(rk[ROUNDS]);
			Substitution(Si);
			ShiftRow(shifts1SC);

			//
			// ROUNDS-1 ordinary rounds
			//
			for (r = ROUNDS - 1; r > 0; r--)
			{
				KeyAddition(rk[r]);
				InvMixColumn();
				Substitution(Si);
				ShiftRow(shifts1SC);
			}

			//
			// End with the extra key addition
			//
			KeyAddition(rk[0]);
		}
	}

}