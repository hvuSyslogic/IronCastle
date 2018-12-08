using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.util
{

	/// <summary>
	/// BigInteger utilities.
	/// </summary>
	public sealed class BigIntegers
	{
		public static readonly BigInteger ZERO = BigInteger.valueOf(0);
		public static readonly BigInteger ONE = BigInteger.valueOf(1);

		private static readonly BigInteger TWO = BigInteger.valueOf(2);
		private static readonly BigInteger THREE = BigInteger.valueOf(3);

		private const int MAX_ITERATIONS = 1000;

		/// <summary>
		/// Return the passed in value as an unsigned byte array.
		/// </summary>
		/// <param name="value"> value to be converted. </param>
		/// <returns> a byte array without a leading zero byte if present in the signed encoding. </returns>
		public static byte[] asUnsignedByteArray(BigInteger value)
		{
			byte[] bytes = value.toByteArray();

			if (bytes[0] == 0)
			{
				byte[] tmp = new byte[bytes.Length - 1];

				JavaSystem.arraycopy(bytes, 1, tmp, 0, tmp.Length);

				return tmp;
			}

			return bytes;
		}

		/// <summary>
		/// Return the passed in value as an unsigned byte array.
		/// </summary>
		/// <param name="value"> value to be converted. </param>
		/// <returns> a byte array without a leading zero byte if present in the signed encoding. </returns>
		public static byte[] asUnsignedByteArray(int length, BigInteger value)
		{
			byte[] bytes = value.toByteArray();
			if (bytes.Length == length)
			{
				return bytes;
			}

			int start = bytes[0] == 0 ? 1 : 0;
			int count = bytes.Length - start;

			if (count > length)
			{
				throw new IllegalArgumentException("standard length exceeded for value");
			}

			byte[] tmp = new byte[length];
			JavaSystem.arraycopy(bytes, start, tmp, tmp.Length - count, count);
			return tmp;
		}

		/// <summary>
		/// Return a random BigInteger not less than 'min' and not greater than 'max'
		/// </summary>
		/// <param name="min"> the least value that may be generated </param>
		/// <param name="max"> the greatest value that may be generated </param>
		/// <param name="random"> the source of randomness </param>
		/// <returns> a random BigInteger value in the range [min,max] </returns>
		public static BigInteger createRandomInRange(BigInteger min, BigInteger max, SecureRandom random)
		{
			int cmp = min.compareTo(max);
			if (cmp >= 0)
			{
				if (cmp > 0)
				{
					throw new IllegalArgumentException("'min' may not be greater than 'max'");
				}

				return min;
			}

			if (min.bitLength() > max.bitLength() / 2)
			{
				return createRandomInRange(ZERO, max.subtract(min), random).add(min);
			}

			for (int i = 0; i < MAX_ITERATIONS; ++i)
			{
				BigInteger x = createRandomBigInteger(max.bitLength(), random);
				if (x.compareTo(min) >= 0 && x.compareTo(max) <= 0)
				{
					return x;
				}
			}

			// fall back to a faster (restricted) method
			return createRandomBigInteger(max.subtract(min).bitLength() - 1, random).add(min);
		}

		public static BigInteger fromUnsignedByteArray(byte[] buf)
		{
			return new BigInteger(1, buf);
		}

		public static BigInteger fromUnsignedByteArray(byte[] buf, int off, int length)
		{
			byte[] mag = buf;
			if (off != 0 || length != buf.Length)
			{
				mag = new byte[length];
				JavaSystem.arraycopy(buf, off, mag, 0, length);
			}
			return new BigInteger(1, mag);
		}

		public static int getUnsignedByteLength(BigInteger n)
		{
			return (n.bitLength() + 7) / 8;
		}

		/// <summary>
		/// Return a positive BigInteger in the range of 0 to 2**bitLength - 1.
		/// </summary>
		/// <param name="bitLength"> maximum bit length for the generated BigInteger. </param>
		/// <param name="random"> a source of randomness. </param>
		/// <returns> a positive BigInteger </returns>
		public static BigInteger createRandomBigInteger(int bitLength, SecureRandom random)
		{
			return new BigInteger(1, createRandom(bitLength, random));
		}

		/// <summary>
		/// Return a prime number candidate of the specified bit length.
		/// </summary>
		/// <param name="bitLength"> bit length for the generated BigInteger. </param>
		/// <param name="random"> a source of randomness. </param>
		/// <returns> a positive BigInteger of numBits length </returns>
		public static BigInteger createRandomPrime(int bitLength, int certainty, SecureRandom random)
		{
			if (bitLength < 2)
			{
				throw new IllegalArgumentException("bitLength < 2");
			}

			BigInteger rv;

			if (bitLength == 2)
			{
				return (random.nextInt() < 0) ? TWO : THREE;
			}

			do
			{
				byte[] @base = createRandom(bitLength, random);

				int xBits = 8 * @base.Length - bitLength;
				byte lead = (byte)(1 << (7 - xBits));

				// ensure top and bottom bit set
				@base[0] |= lead;
				@base[@base.Length - 1] |= 0x01;

				rv = new BigInteger(1, @base);
			} while (!rv.isProbablePrime(certainty));

			return rv;
		}

		private static byte[] createRandom(int bitLength, SecureRandom random)
		{
			if (bitLength < 1)
			{
				throw new IllegalArgumentException("bitLength must be at least 1");
			}

			int nBytes = (bitLength + 7) / 8;

			byte[] rv = new byte[nBytes];

			random.nextBytes(rv);

			// strip off any excess bits in the MSB
			int xBits = 8 * nBytes - bitLength;
			rv[0] &= (byte)((int)((uint)255 >> xBits));

			return rv;
		}
	}

}