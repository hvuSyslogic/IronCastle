namespace org.bouncycastle.crypto.test
{

	using GCMExponentiator = org.bouncycastle.crypto.modes.gcm.GCMExponentiator;
	using GCMMultiplier = org.bouncycastle.crypto.modes.gcm.GCMMultiplier;
	using Tables1kGCMExponentiator = org.bouncycastle.crypto.modes.gcm.Tables1kGCMExponentiator;
	using Tables4kGCMMultiplier = org.bouncycastle.crypto.modes.gcm.Tables4kGCMMultiplier;
	using Arrays = org.bouncycastle.util.Arrays;
	using Pack = org.bouncycastle.util.Pack;
	using Hex = org.bouncycastle.util.encoders.Hex;

	using TestCase = junit.framework.TestCase;

	public class GCMReorderTest : TestCase
	{
		private static readonly byte[] H;
		private static readonly SecureRandom random = new SecureRandom();
		private static readonly GCMMultiplier mul = new Tables4kGCMMultiplier();
		private static readonly GCMExponentiator exp = new Tables1kGCMExponentiator();
		private static readonly byte[] EMPTY = new byte[0];

		static GCMReorderTest()
		{
			H = new byte[16];
			random.nextBytes(H);
			mul.init(Arrays.clone(H));
			exp.init(Arrays.clone(H));
		}

		public virtual void testCombine()
		{
			for (int count = 0; count < 10; ++count)
			{
				byte[] A = randomBytes(1000);
				byte[] C = randomBytes(1000);

				byte[] ghashA_ = GHASH(A, EMPTY);
				byte[] ghash_C = GHASH(EMPTY, C);
				byte[] ghashAC = GHASH(A, C);

				byte[] ghashCombine = combine_GHASH(ghashA_, (long)A.Length * 8, ghash_C, (long)C.Length * 8);

				assertTrue(Arrays.areEqual(ghashAC, ghashCombine));
			}
		}

		public virtual void testConcatAuth()
		{
			for (int count = 0; count < 10; ++count)
			{
				byte[] P = randomBlocks(100);
				byte[] A = randomBytes(1000);
				byte[] PA = concatArrays(P, A);

				byte[] ghashP_ = GHASH(P, EMPTY);
				byte[] ghashA_ = GHASH(A, EMPTY);
				byte[] ghashPA_ = GHASH(PA, EMPTY);
				byte[] ghashConcat = concatAuth_GHASH(ghashP_, (long)P.Length * 8, ghashA_, (long)A.Length * 8);

				assertTrue(Arrays.areEqual(ghashPA_, ghashConcat));
			}
		}

		public virtual void testConcatCrypt()
		{
			for (int count = 0; count < 10; ++count)
			{
				byte[] P = randomBlocks(100);
				byte[] A = randomBytes(1000);
				byte[] PA = concatArrays(P, A);

				byte[] ghash_P = GHASH(EMPTY, P);
				byte[] ghash_A = GHASH(EMPTY, A);
				byte[] ghash_PA = GHASH(EMPTY, PA);
				byte[] ghashConcat = concatCrypt_GHASH(ghash_P, (long)P.Length * 8, ghash_A, (long)A.Length * 8);

				assertTrue(Arrays.areEqual(ghash_PA, ghashConcat));
			}
		}

		public virtual void testExp()
		{
			{
				byte[] buf1 = new byte[16];
				buf1[0] = unchecked((byte)0x80);

				byte[] buf2 = new byte[16];

				for (int pow = 0; pow != 100; ++pow)
				{
					exp.exponentiateX(pow, buf2);

					assertTrue(Arrays.areEqual(buf1, buf2));

					mul.multiplyH(buf1);
				}
			}

			long[] testPow = new long[]{10, 1, 8, 17, 24, 13, 2, 13, 2, 3};
			byte[][] testData = new byte[][]{Hex.decode("9185848a877bd87ba071e281f476e8e7"), Hex.decode("697ce3052137d80745d524474fb6b290"), Hex.decode("2696fc47198bb23b11296e4f88720a17"), Hex.decode("01f2f0ead011a4ae0cf3572f1b76dd8e"), Hex.decode("a53060694a044e4b7fa1e661c5a7bb6b"), Hex.decode("39c0392e8b6b0e04a7565c85394c2c4c"), Hex.decode("519c362d502e07f2d8b7597a359a5214"), Hex.decode("5a527a393675705e19b2117f67695af4"), Hex.decode("27fc0901d1d332a53ba4d4386c2109d2"), Hex.decode("93ca9b57174aabedf8220e83366d7df6")};

			for (int i = 0; i != 10; ++i)
			{
				long pow = testPow[i];
				byte[] data = Arrays.clone(testData[i]);

				byte[] expected = Arrays.clone(data);
				for (int j = 0; j < pow; ++j)
				{
					mul.multiplyH(expected);
				}

				byte[] H_a = new byte[16];
				exp.exponentiateX(pow, H_a);
				byte[] actual = multiply(data, H_a);

				assertTrue(Arrays.areEqual(expected, actual));
			}
		}

		public virtual void testMultiply()
		{
			byte[] expected = Arrays.clone(H);
			mul.multiplyH(expected);

			assertTrue(Arrays.areEqual(expected, multiply(H, H)));

			for (int count = 0; count < 10; ++count)
			{
				byte[] a = new byte[16];
				random.nextBytes(a);

				byte[] b = new byte[16];
				random.nextBytes(b);

				expected = Arrays.clone(a);
				mul.multiplyH(expected);
				assertTrue(Arrays.areEqual(expected, multiply(a, H)));
				assertTrue(Arrays.areEqual(expected, multiply(H, a)));

				expected = Arrays.clone(b);
				mul.multiplyH(expected);
				assertTrue(Arrays.areEqual(expected, multiply(b, H)));
				assertTrue(Arrays.areEqual(expected, multiply(H, b)));

				assertTrue(Arrays.areEqual(multiply(a, b), multiply(b, a)));
			}
		}

		private byte[] randomBlocks(int upper)
		{
			byte[] bs = new byte[16 * random.nextInt(upper)];
			random.nextBytes(bs);
			return bs;
		}

		private byte[] randomBytes(int upper)
		{
			byte[] bs = new byte[random.nextInt(upper)];
			random.nextBytes(bs);
			return bs;
		}

		private byte[] concatArrays(byte[] a, byte[] b)
		{
			byte[] ab = new byte[a.Length + b.Length];
			JavaSystem.arraycopy(a, 0, ab, 0, a.Length);
			JavaSystem.arraycopy(b, 0, ab, a.Length, b.Length);
			return ab;
		}

		private byte[] combine_GHASH(byte[] ghashA_, long bitlenA, byte[] ghash_C, long bitlenC)
		{
			// Note: bitlenA must be aligned to the block size

			long c = (long)((ulong)(bitlenC + 127) >> 7);

			byte[] H_c = new byte[16];
			exp.exponentiateX(c, H_c);

			byte[] tmp1 = lengthBlock(bitlenA, 0);
			mul.multiplyH(tmp1);

			byte[] ghashAC = Arrays.clone(ghashA_);
			xor(ghashAC, tmp1);
			ghashAC = multiply(ghashAC, H_c);
			// No need to touch the len(C) part (second 8 bytes)
			xor(ghashAC, tmp1);
			xor(ghashAC, ghash_C);

			return ghashAC;
		}

		private byte[] concatAuth_GHASH(byte[] ghashP, long bitlenP, byte[] ghashA, long bitlenA)
		{
			// Note: bitlenP must be aligned to the block size

			long a = (long)((ulong)(bitlenA + 127) >> 7);

			byte[] tmp1 = lengthBlock(bitlenP, 0);
			mul.multiplyH(tmp1);

			byte[] tmp2 = lengthBlock(bitlenA ^ (bitlenP + bitlenA), 0);
			mul.multiplyH(tmp2);

			byte[] H_a = new byte[16];
			exp.exponentiateX(a, H_a);

			byte[] ghashC = Arrays.clone(ghashP);
			xor(ghashC, tmp1);
			ghashC = multiply(ghashC, H_a);
			xor(ghashC, tmp2);
			xor(ghashC, ghashA);
			return ghashC;
		}

		private byte[] concatCrypt_GHASH(byte[] ghashP, long bitlenP, byte[] ghashA, long bitlenA)
		{
			// Note: bitlenP must be aligned to the block size

			long a = (long)((ulong)(bitlenA + 127) >> 7);

			byte[] tmp1 = lengthBlock(0, bitlenP);
			mul.multiplyH(tmp1);

			byte[] tmp2 = lengthBlock(0, bitlenA ^ (bitlenP + bitlenA));
			mul.multiplyH(tmp2);

			byte[] H_a = new byte[16];
			exp.exponentiateX(a, H_a);

			byte[] ghashC = Arrays.clone(ghashP);
			xor(ghashC, tmp1);
			ghashC = multiply(ghashC, H_a);
			xor(ghashC, tmp2);
			xor(ghashC, ghashA);
			return ghashC;
		}

		private byte[] GHASH(byte[] A, byte[] C)
		{
			byte[] X = new byte[16];

			{
				for (int pos = 0; pos < A.Length; pos += 16)
				{
					byte[] tmp = new byte[16];
					int num = Math.Min(A.Length - pos, 16);
					JavaSystem.arraycopy(A, pos, tmp, 0, num);
					xor(X, tmp);
					mul.multiplyH(X);
				}
			}

			{
				for (int pos = 0; pos < C.Length; pos += 16)
				{
					byte[] tmp = new byte[16];
					int num = Math.Min(C.Length - pos, 16);
					JavaSystem.arraycopy(C, pos, tmp, 0, num);
					xor(X, tmp);
					mul.multiplyH(X);
				}
			}

			{
				xor(X, lengthBlock((long)A.Length * 8, (long)C.Length * 8));
				mul.multiplyH(X);
			}

			return X;
		}

		private static byte[] lengthBlock(long bitlenA, long bitlenC)
		{
			byte[] tmp = new byte[16];
			Pack.longToBigEndian(bitlenA, tmp, 0);
			Pack.longToBigEndian(bitlenC, tmp, 8);
			return tmp;
		}

		private static void xor(byte[] block, byte[] val)
		{
			for (int i = 15; i >= 0; --i)
			{
				block[i] ^= val[i];
			}
		}

		private static byte[] multiply(byte[] a, byte[] b)
		{
			byte[] c = new byte[16];
			byte[] tmp = Arrays.clone(b);

			for (int i = 0; i < 16; ++i)
			{
				byte bits = a[i];
				for (int j = 7; j >= 0; --j)
				{
					if ((bits & (1 << j)) != 0)
					{
						xor(c, tmp);
					}

					bool lsb = (tmp[15] & 1) != 0;
					shiftRight(tmp);
					if (lsb)
					{
						// R = new byte[]{ 0xe1, ... };
	//                    GCMUtil.xor(v, R);
						tmp[0] ^= unchecked((byte)0xe1);
					}
				}
			}

			return c;
		}

		private static void shiftRight(byte[] block)
		{
			int i = 0;
			int bit = 0;
			for (;;)
			{
				int b = block[i] & 0xff;
				block[i] = (byte)(((int)((uint)b >> 1)) | bit);
				if (++i == 16)
				{
					break;
				}
				bit = (b & 1) << 7;
			}
		}
	}

}