using System.IO;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.pqc.math.ntru.util
{

	using IntEuclidean = org.bouncycastle.pqc.math.ntru.euclid.IntEuclidean;
	using DenseTernaryPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
	using SparseTernaryPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial;
	using TernaryPolynomial = org.bouncycastle.pqc.math.ntru.polynomial.TernaryPolynomial;
	using Integers = org.bouncycastle.util.Integers;

	public class Util
	{
		private static volatile bool IS_64_BITNESS_KNOWN;
		private static volatile bool IS_64_BIT_JVM;

		/// <summary>
		/// Calculates the inverse of n mod modulus
		/// </summary>
		public static int invert(int n, int modulus)
		{
			n %= modulus;
			if (n < 0)
			{
				n += modulus;
			}
			return IntEuclidean.calculate(n, modulus).x;
		}

		/// <summary>
		/// Calculates a^b mod modulus
		/// </summary>
		public static int pow(int a, int b, int modulus)
		{
			int p = 1;
			for (int i = 0; i < b; i++)
			{
				p = (p * a) % modulus;
			}
			return p;
		}

		/// <summary>
		/// Calculates a^b mod modulus
		/// </summary>
		public static long pow(long a, int b, long modulus)
		{
			long p = 1;
			for (int i = 0; i < b; i++)
			{
				p = (p * a) % modulus;
			}
			return p;
		}

		/// <summary>
		/// Generates a "sparse" or "dense" polynomial containing numOnes ints equal to 1,
		/// numNegOnes int equal to -1, and the rest equal to 0.
		/// </summary>
		/// <param name="N"> </param>
		/// <param name="numOnes"> </param>
		/// <param name="numNegOnes"> </param>
		/// <param name="sparse">     whether to create a <seealso cref="SparseTernaryPolynomial"/> or <seealso cref="DenseTernaryPolynomial"/> </param>
		/// <returns> a ternary polynomial </returns>
		public static TernaryPolynomial generateRandomTernary(int N, int numOnes, int numNegOnes, bool sparse, SecureRandom random)
		{
			if (sparse)
			{
				return SparseTernaryPolynomial.generateRandom(N, numOnes, numNegOnes, random);
			}
			else
			{
				return DenseTernaryPolynomial.generateRandom(N, numOnes, numNegOnes, random);
			}
		}

		/// <summary>
		/// Generates an array containing numOnes ints equal to 1,
		/// numNegOnes int equal to -1, and the rest equal to 0.
		/// </summary>
		/// <param name="N"> </param>
		/// <param name="numOnes"> </param>
		/// <param name="numNegOnes"> </param>
		/// <returns> an array of integers </returns>
		public static int[] generateRandomTernary(int N, int numOnes, int numNegOnes, SecureRandom random)
		{
			int? one = Integers.valueOf(1);
			int? minusOne = Integers.valueOf(-1);
			int? zero = Integers.valueOf(0);

			List list = new ArrayList();
			for (int i = 0; i < numOnes; i++)
			{
				list.add(one);
			}
			for (int i = 0; i < numNegOnes; i++)
			{
				list.add(minusOne);
			}
			while (list.size() < N)
			{
				list.add(zero);
			}

			Collections.shuffle(list, random);

			int[] arr = new int[N];
			for (int i = 0; i < N; i++)
			{
				arr[i] = ((int?)list.get(i)).Value;
			}
			return arr;
		}

		/// <summary>
		/// Takes an educated guess as to whether 64 bits are supported by the JVM.
		/// </summary>
		/// <returns> <code>true</code> if 64-bit support detected, <code>false</code> otherwise </returns>
		public static bool is64BitJVM()
		{
			if (!IS_64_BITNESS_KNOWN)
			{
				string arch = System.getProperty("os.arch");
				string sunModel = System.getProperty("sun.arch.data.model");
				IS_64_BIT_JVM = "amd64".Equals(arch) || "x86_64".Equals(arch) || "ppc64".Equals(arch) || "64".Equals(sunModel);
				IS_64_BITNESS_KNOWN = true;
			}
			return IS_64_BIT_JVM;
		}

		/// <summary>
		/// Reads a given number of bytes from an <code>InputStream</code>.
		/// If there are not enough bytes in the stream, an <code>IOException</code>
		/// is thrown.
		/// </summary>
		/// <param name="is"> </param>
		/// <param name="length"> </param>
		/// <returns> an array of length <code>length</code> </returns>
		/// <exception cref="IOException"> </exception>
		public static byte[] readFullLength(InputStream @is, int length)
		{
			byte[] arr = new byte[length];
			if (@is.read(arr) != arr.Length)
			{
				throw new IOException("Not enough bytes to read.");
			}
			return arr;
		}
	}
}