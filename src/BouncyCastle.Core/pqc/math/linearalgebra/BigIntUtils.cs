﻿using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.pqc.math.linearalgebra
{

	/// <summary>
	/// FIXME: is this really necessary?!
	/// </summary>
	public sealed class BigIntUtils
	{

		/// <summary>
		/// Default constructor (private).
		/// </summary>
		private BigIntUtils()
		{
			// empty
		}

		/// <summary>
		/// Checks if two BigInteger arrays contain the same entries
		/// </summary>
		/// <param name="a"> first BigInteger array </param>
		/// <param name="b"> second BigInteger array </param>
		/// <returns> true or false </returns>
		public static bool Equals(BigInteger[] a, BigInteger[] b)
		{
			int flag = 0;

			if (a.Length != b.Length)
			{
				return false;
			}
			for (int i = 0; i < a.Length; i++)
			{
				// avoid branches here!
				// problem: compareTo on BigIntegers is not
				// guaranteed constant-time!
				flag |= a[i].compareTo(b[i]);
			}
			return flag == 0;
		}

		/// <summary>
		/// Fill the given BigInteger array with the given value.
		/// </summary>
		/// <param name="array"> the array </param>
		/// <param name="value"> the value </param>
		public static void fill(BigInteger[] array, BigInteger value)
		{
			for (int i = array.Length - 1; i >= 0; i--)
			{
				array[i] = value;
			}
		}

		/// <summary>
		/// Generates a subarray of a given BigInteger array.
		/// </summary>
		/// <param name="input"> -
		///              the input BigInteger array </param>
		/// <param name="start"> -
		///              the start index </param>
		/// <param name="end">   -
		///              the end index </param>
		/// <returns> a subarray of <tt>input</tt>, ranging from <tt>start</tt> to
		///         <tt>end</tt> </returns>
		public static BigInteger[] subArray(BigInteger[] input, int start, int end)
		{
			BigInteger[] result = new BigInteger[end - start];
			JavaSystem.arraycopy(input, start, result, 0, end - start);
			return result;
		}

		/// <summary>
		/// Converts a BigInteger array into an integer array
		/// </summary>
		/// <param name="input"> -
		///              the BigInteger array </param>
		/// <returns> the integer array </returns>
		public static int[] toIntArray(BigInteger[] input)
		{
			int[] result = new int[input.Length];
			for (int i = 0; i < input.Length; i++)
			{
				result[i] = input[i].intValue();
			}
			return result;
		}

		/// <summary>
		/// Converts a BigInteger array into an integer array, reducing all
		/// BigIntegers mod q.
		/// </summary>
		/// <param name="q">     -
		///              the modulus </param>
		/// <param name="input"> -
		///              the BigInteger array </param>
		/// <returns> the integer array </returns>
		public static int[] toIntArrayModQ(int q, BigInteger[] input)
		{
			BigInteger bq = BigInteger.valueOf(q);
			int[] result = new int[input.Length];
			for (int i = 0; i < input.Length; i++)
			{
				result[i] = input[i].mod(bq).intValue();
			}
			return result;
		}

		/// <summary>
		/// Return the value of <tt>big</tt> as a byte array. Although BigInteger
		/// has such a method, it uses an extra bit to indicate the sign of the
		/// number. For elliptic curve cryptography, the numbers usually are
		/// positive. Thus, this helper method returns a byte array of minimal
		/// length, ignoring the sign of the number.
		/// </summary>
		/// <param name="value"> the <tt>BigInteger</tt> value to be converted to a byte
		///              array </param>
		/// <returns> the value <tt>big</tt> as byte array </returns>
		public static byte[] toMinimalByteArray(BigInteger value)
		{
			byte[] valBytes = value.toByteArray();
			if ((valBytes.Length == 1) || (value.bitLength() & 0x07) != 0)
			{
				return valBytes;
			}
			byte[] result = new byte[value.bitLength() >> 3];
			JavaSystem.arraycopy(valBytes, 1, result, 0, result.Length);
			return result;
		}

	}

}