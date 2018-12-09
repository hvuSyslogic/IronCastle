﻿using org.bouncycastle.Port;

namespace org.bouncycastle.pqc.math.linearalgebra
{
	/// <summary>
	/// This class is a utility class for manipulating byte arrays.
	/// </summary>
	public sealed class ByteUtils
	{

		private static readonly char[] HEX_CHARS = new char[] {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

		/// <summary>
		/// Default constructor (private)
		/// </summary>
		private ByteUtils()
		{
			// empty
		}

		/// <summary>
		/// Compare two byte arrays (perform null checks beforehand).
		/// </summary>
		/// <param name="left">  the first byte array </param>
		/// <param name="right"> the second byte array </param>
		/// <returns> the result of the comparison </returns>
		public static bool Equals(byte[] left, byte[] right)
		{
			if (left == null)
			{
				return right == null;
			}
			if (right == null)
			{
				return false;
			}

			if (left.Length != right.Length)
			{
				return false;
			}
			bool result = true;
			for (int i = left.Length - 1; i >= 0; i--)
			{
				result &= left[i] == right[i];
			}
			return result;
		}

		/// <summary>
		/// Compare two two-dimensional byte arrays. No null checks are performed.
		/// </summary>
		/// <param name="left">  the first byte array </param>
		/// <param name="right"> the second byte array </param>
		/// <returns> the result of the comparison </returns>
		public static bool Equals(byte[][] left, byte[][] right)
		{
			if (left.Length != right.Length)
			{
				return false;
			}

			bool result = true;
			for (int i = left.Length - 1; i >= 0; i--)
			{
				result &= ByteUtils.Equals(left[i], right[i]);
			}

			return result;
		}

		/// <summary>
		/// Compare two three-dimensional byte arrays. No null checks are performed.
		/// </summary>
		/// <param name="left">  the first byte array </param>
		/// <param name="right"> the second byte array </param>
		/// <returns> the result of the comparison </returns>
		public static bool Equals(byte[][][] left, byte[][][] right)
		{
			if (left.Length != right.Length)
			{
				return false;
			}

			bool result = true;
			for (int i = left.Length - 1; i >= 0; i--)
			{
				if (left[i].Length != right[i].Length)
				{
					return false;
				}
				for (int j = left[i].Length - 1; j >= 0; j--)
				{
					result &= ByteUtils.Equals(left[i][j], right[i][j]);
				}
			}

			return result;
		}

		/// <summary>
		/// Computes a hashcode based on the contents of a one-dimensional byte array
		/// rather than its identity.
		/// </summary>
		/// <param name="array"> the array to compute the hashcode of </param>
		/// <returns> the hashcode </returns>
		public static int deepHashCode(byte[] array)
		{
			int result = 1;
			for (int i = 0; i < array.Length; i++)
			{
				result = 31 * result + array[i];
			}
			return result;
		}

		/// <summary>
		/// Computes a hashcode based on the contents of a two-dimensional byte array
		/// rather than its identity.
		/// </summary>
		/// <param name="array"> the array to compute the hashcode of </param>
		/// <returns> the hashcode </returns>
		public static int deepHashCode(byte[][] array)
		{
			int result = 1;
			for (int i = 0; i < array.Length; i++)
			{
				result = 31 * result + deepHashCode(array[i]);
			}
			return result;
		}

		/// <summary>
		/// Computes a hashcode based on the contents of a three-dimensional byte
		/// array rather than its identity.
		/// </summary>
		/// <param name="array"> the array to compute the hashcode of </param>
		/// <returns> the hashcode </returns>
		public static int deepHashCode(byte[][][] array)
		{
			int result = 1;
			for (int i = 0; i < array.Length; i++)
			{
				result = 31 * result + deepHashCode(array[i]);
			}
			return result;
		}


		/// <summary>
		/// Return a clone of the given byte array (performs null check beforehand).
		/// </summary>
		/// <param name="array"> the array to clone </param>
		/// <returns> the clone of the given array, or <tt>null</tt> if the array is
		///         <tt>null</tt> </returns>
		public static byte[] clone(byte[] array)
		{
			if (array == null)
			{
				return null;
			}
			byte[] result = new byte[array.Length];
			JavaSystem.arraycopy(array, 0, result, 0, array.Length);
			return result;
		}

		/// <summary>
		/// Convert a string containing hexadecimal characters to a byte-array.
		/// </summary>
		/// <param name="s"> a hex string </param>
		/// <returns> a byte array with the corresponding value </returns>
		public static byte[] fromHexString(string s)
		{
			char[] rawChars = s.ToUpper().ToCharArray();

			int hexChars = 0;
			for (int i = 0; i < rawChars.Length; i++)
			{
				if ((rawChars[i] >= '0' && rawChars[i] <= '9') || (rawChars[i] >= 'A' && rawChars[i] <= 'F'))
				{
					hexChars++;
				}
			}

			byte[] byteString = new byte[(hexChars + 1) >> 1];

			int pos = hexChars & 1;

			for (int i = 0; i < rawChars.Length; i++)
			{
				if (rawChars[i] >= '0' && rawChars[i] <= '9')
				{
					byteString[pos >> 1] <<= 4;
					byteString[pos >> 1] |= (byte)(rawChars[i] - '0');
				}
				else if (rawChars[i] >= 'A' && rawChars[i] <= 'F')
				{
					byteString[pos >> 1] <<= 4;
					byteString[pos >> 1] |= (byte)(rawChars[i] - 'A') + 10;
				}
				else
				{
					continue;
				}
				pos++;
			}

			return byteString;
		}

		/// <summary>
		/// Convert a byte array to the corresponding hexstring.
		/// </summary>
		/// <param name="input"> the byte array to be converted </param>
		/// <returns> the corresponding hexstring </returns>
		public static string toHexString(byte[] input)
		{
			string result = "";
			for (int i = 0; i < input.Length; i++)
			{
				result += HEX_CHARS[((int)((uint)input[i] >> 4)) & 0x0f];
				result += HEX_CHARS[(input[i]) & 0x0f];
			}
			return result;
		}

		/// <summary>
		/// Convert a byte array to the corresponding hex string.
		/// </summary>
		/// <param name="input">     the byte array to be converted </param>
		/// <param name="prefix">    the prefix to put at the beginning of the hex string </param>
		/// <param name="seperator"> a separator string </param>
		/// <returns> the corresponding hex string </returns>
		public static string toHexString(byte[] input, string prefix, string seperator)
		{
			string result = prefix;
			for (int i = 0; i < input.Length; i++)
			{
				result += HEX_CHARS[((int)((uint)input[i] >> 4)) & 0x0f];
				result += HEX_CHARS[(input[i]) & 0x0f];
				if (i < input.Length - 1)
				{
					result += seperator;
				}
			}
			return result;
		}

		/// <summary>
		/// Convert a byte array to the corresponding bit string.
		/// </summary>
		/// <param name="input"> the byte array to be converted </param>
		/// <returns> the corresponding bit string </returns>
		public static string toBinaryString(byte[] input)
		{
			string result = "";
			int i;
			for (i = 0; i < input.Length; i++)
			{
				int e = input[i];
				for (int ii = 0; ii < 8; ii++)
				{
					int b = ((int)((uint)e >> ii)) & 1;
					result += b;
				}
				if (i != input.Length - 1)
				{
					result += " ";
				}
			}
			return result;
		}

		/// <summary>
		/// Compute the bitwise XOR of two arrays of bytes. The arrays have to be of
		/// same length. No length checking is performed.
		/// </summary>
		/// <param name="x1"> the first array </param>
		/// <param name="x2"> the second array </param>
		/// <returns> x1 XOR x2 </returns>
		public static byte[] xor(byte[] x1, byte[] x2)
		{
			byte[] @out = new byte[x1.Length];

			for (int i = x1.Length - 1; i >= 0; i--)
			{
				@out[i] = (byte)(x1[i] ^ x2[i]);
			}
			return @out;
		}

		/// <summary>
		/// Concatenate two byte arrays. No null checks are performed.
		/// </summary>
		/// <param name="x1"> the first array </param>
		/// <param name="x2"> the second array </param>
		/// <returns> (x2||x1) (little-endian order, i.e. x1 is at lower memory
		///         addresses) </returns>
		public static byte[] concatenate(byte[] x1, byte[] x2)
		{
			byte[] result = new byte[x1.Length + x2.Length];

			JavaSystem.arraycopy(x1, 0, result, 0, x1.Length);
			JavaSystem.arraycopy(x2, 0, result, x1.Length, x2.Length);

			return result;
		}

		/// <summary>
		/// Convert a 2-dimensional byte array into a 1-dimensional byte array by
		/// concatenating all entries.
		/// </summary>
		/// <param name="array"> a 2-dimensional byte array </param>
		/// <returns> the concatenated input array </returns>
		public static byte[] concatenate(byte[][] array)
		{
			int rowLength = array[0].Length;
			byte[] result = new byte[array.Length * rowLength];
			int index = 0;
			for (int i = 0; i < array.Length; i++)
			{
				JavaSystem.arraycopy(array[i], 0, result, index, rowLength);
				index += rowLength;
			}
			return result;
		}

		/// <summary>
		/// Split a byte array <tt>input</tt> into two arrays at <tt>index</tt>,
		/// i.e. the first array will have the lower <tt>index</tt> bytes, the
		/// second one the higher <tt>input.length - index</tt> bytes.
		/// </summary>
		/// <param name="input"> the byte array to be split </param>
		/// <param name="index"> the index where the byte array is split </param>
		/// <returns> the splitted input array as an array of two byte arrays </returns>
		/// <exception cref="ArrayIndexOutOfBoundsException"> if <tt>index</tt> is out of bounds </exception>
		public static byte[][] split(byte[] input, int index)
		{
			if (index > input.Length)
			{
				throw new ArrayIndexOutOfBoundsException();
			}
			byte[][] result = new byte[2][];
			result[0] = new byte[index];
			result[1] = new byte[input.Length - index];
			JavaSystem.arraycopy(input, 0, result[0], 0, index);
			JavaSystem.arraycopy(input, index, result[1], 0, input.Length - index);
			return result;
		}

		/// <summary>
		/// Generate a subarray of a given byte array.
		/// </summary>
		/// <param name="input"> the input byte array </param>
		/// <param name="start"> the start index </param>
		/// <param name="end">   the end index </param>
		/// <returns> a subarray of <tt>input</tt>, ranging from <tt>start</tt>
		///         (inclusively) to <tt>end</tt> (exclusively) </returns>
		public static byte[] subArray(byte[] input, int start, int end)
		{
			byte[] result = new byte[end - start];
			JavaSystem.arraycopy(input, start, result, 0, end - start);
			return result;
		}

		/// <summary>
		/// Generate a subarray of a given byte array.
		/// </summary>
		/// <param name="input"> the input byte array </param>
		/// <param name="start"> the start index </param>
		/// <returns> a subarray of <tt>input</tt>, ranging from <tt>start</tt> to
		///         the end of the array </returns>
		public static byte[] subArray(byte[] input, int start)
		{
			return subArray(input, start, input.Length);
		}

		/// <summary>
		/// Rewrite a byte array as a char array
		/// </summary>
		/// <param name="input"> -
		///              the byte array </param>
		/// <returns> char array </returns>
		public static char[] toCharArray(byte[] input)
		{
			char[] result = new char[input.Length];
			for (int i = 0; i < input.Length; i++)
			{
				result[i] = (char)input[i];
			}
			return result;
		}

	}

}