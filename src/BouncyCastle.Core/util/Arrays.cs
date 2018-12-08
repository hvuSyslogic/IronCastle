using System;
using BouncyCastle.Core.Port;
using BouncyCastle.Core.Port.java.lang;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.util
{

	/// <summary>
	/// General array utilities.
	/// </summary>
	public sealed class Arrays
	{
		private Arrays()
		{
			// static class, hide constructor
		}

		public static bool areAllZeroes(byte[] buf, int off, int len)
		{
			int bits = 0;
			for (int i = 0; i < len; ++i)
			{
				bits |= buf[off + i];
			}
			return bits == 0;
		}

		public static bool areEqual(bool[] a, bool[] b)
		{
			if (a == b)
			{
				return true;
			}

			if (a == null || b == null)
			{
				return false;
			}

			if (a.Length != b.Length)
			{
				return false;
			}

			for (int i = 0; i != a.Length; i++)
			{
				if (a[i] != b[i])
				{
					return false;
				}
			}

			return true;
		}

		public static bool areEqual(char[] a, char[] b)
		{
			if (a == b)
			{
				return true;
			}

			if (a == null || b == null)
			{
				return false;
			}

			if (a.Length != b.Length)
			{
				return false;
			}

			for (int i = 0; i != a.Length; i++)
			{
				if (a[i] != b[i])
				{
					return false;
				}
			}

			return true;
		}

		public static bool areEqual(byte[] a, byte[] b)
		{
			if (a == b)
			{
				return true;
			}

			if (a == null || b == null)
			{
				return false;
			}

			if (a.Length != b.Length)
			{
				return false;
			}

			for (int i = 0; i != a.Length; i++)
			{
				if (a[i] != b[i])
				{
					return false;
				}
			}

			return true;
		}

		public static bool areEqual(short[] a, short[] b)
		{
			if (a == b)
			{
				return true;
			}

			if (a == null || b == null)
			{
				return false;
			}

			if (a.Length != b.Length)
			{
				return false;
			}

			for (int i = 0; i != a.Length; i++)
			{
				if (a[i] != b[i])
				{
					return false;
				}
			}

			return true;
		}

		/// <summary>
		/// A constant time equals comparison - does not terminate early if
		/// test will fail. For best results always pass the expected value
		/// as the first parameter.
		/// </summary>
		/// <param name="expected"> first array </param>
		/// <param name="supplied"> second array </param>
		/// <returns> true if arrays equal, false otherwise. </returns>
		public static bool constantTimeAreEqual(byte[] expected, byte[] supplied)
		{
			if (expected == supplied)
			{
				return true;
			}

			if (expected == null || supplied == null)
			{
				return false;
			}

			if (expected.Length != supplied.Length)
			{
				return !Arrays.constantTimeAreEqual(expected, expected);
			}

			int nonEqual = 0;

			for (int i = 0; i != expected.Length; i++)
			{
				nonEqual |= (expected[i] ^ supplied[i]);
			}

			return nonEqual == 0;
		}

		public static bool areEqual(int[] a, int[] b)
		{
			if (a == b)
			{
				return true;
			}

			if (a == null || b == null)
			{
				return false;
			}

			if (a.Length != b.Length)
			{
				return false;
			}

			for (int i = 0; i != a.Length; i++)
			{
				if (a[i] != b[i])
				{
					return false;
				}
			}

			return true;
		}

		public static bool areEqual(long[] a, long[] b)
		{
			if (a == b)
			{
				return true;
			}

			if (a == null || b == null)
			{
				return false;
			}

			if (a.Length != b.Length)
			{
				return false;
			}

			for (int i = 0; i != a.Length; i++)
			{
				if (a[i] != b[i])
				{
					return false;
				}
			}

			return true;
		}

		public static bool areEqual(object[] a, object[] b)
		{
			if (a == b)
			{
				return true;
			}
			if (a == null || b == null)
			{
				return false;
			}
			if (a.Length != b.Length)
			{
				return false;
			}
			for (int i = 0; i != a.Length; i++)
			{
				object objA = a[i], objB = b[i];
				if (objA == null)
				{
					if (objB != null)
					{
						return false;
					}
				}
				else if (!objA.Equals(objB))
				{
					return false;
				}
			}
			return true;
		}

		public static int compareUnsigned(byte[] a, byte[] b)
		{
			if (a == b)
			{
				return 0;
			}
			if (a == null)
			{
				return -1;
			}
			if (b == null)
			{
				return 1;
			}
			int minLen = Math.min(a.Length, b.Length);
			for (int i = 0; i < minLen; ++i)
			{
				int aVal = a[i] & 0xFF, bVal = b[i] & 0xFF;
				if (aVal < bVal)
				{
					return -1;
				}
				if (aVal > bVal)
				{
					return 1;
				}
			}
			if (a.Length < b.Length)
			{
				return -1;
			}
			if (a.Length > b.Length)
			{
				return 1;
			}
			return 0;
		}

		public static bool contains(short[] a, short n)
		{
			for (int i = 0; i < a.Length; ++i)
			{
				if (a[i] == n)
				{
					return true;
				}
			}
			return false;
		}

		public static bool contains(int[] a, int n)
		{
			for (int i = 0; i < a.Length; ++i)
			{
				if (a[i] == n)
				{
					return true;
				}
			}
			return false;
		}

		public static void fill(byte[] array, byte value)
		{
			for (int i = 0; i < array.Length; i++)
			{
				array[i] = value;
			}
		}

		public static void fill(byte[] array, int start, int finish, byte value)
		{
			for (int i = start; i < finish; i++)
			{
				array[i] = value;
			}
		}

		public static void fill(char[] array, char value)
		{
			for (int i = 0; i < array.Length; i++)
			{
				array[i] = value;
			}
		}

		public static void fill(long[] array, long value)
		{
			for (int i = 0; i < array.Length; i++)
			{
				array[i] = value;
			}
		}

		public static void fill(short[] array, short value)
		{
			for (int i = 0; i < array.Length; i++)
			{
				array[i] = value;
			}
		}

		public static void fill(int[] array, int value)
		{
			for (int i = 0; i < array.Length; i++)
			{
				array[i] = value;
			}
		}

		public static void fill(byte[] array, int @out, byte value)
		{
			if (@out < array.Length)
			{
				for (int i = @out; i < array.Length; i++)
				{
					array[i] = value;
				}
			}
		}

		public static void fill(int[] array, int @out, int value)
		{
			if (@out < array.Length)
			{
				for (int i = @out; i < array.Length; i++)
				{
					array[i] = value;
				}
			}
		}

		public static void fill(short[] array, int @out, short value)
		{
			if (@out < array.Length)
			{
				for (int i = @out; i < array.Length; i++)
				{
					array[i] = value;
				}
			}
		}

		public static void fill(long[] array, int @out, long value)
		{
			if (@out < array.Length)
			{
				for (int i = @out; i < array.Length; i++)
				{
					array[i] = value;
				}
			}
		}

		public static int GetHashCode(byte[] data)
		{
			if (data == null)
			{
				return 0;
			}

			int i = data.Length;
			int hc = i + 1;

			while (--i >= 0)
			{
				hc *= 257;
				hc ^= data[i];
			}

			return hc;
		}

		public static int GetHashCode(byte[] data, int off, int len)
		{
			if (data == null)
			{
				return 0;
			}

			int i = len;
			int hc = i + 1;

			while (--i >= 0)
			{
				hc *= 257;
				hc ^= data[off + i];
			}

			return hc;
		}

		public static int GetHashCode(char[] data)
		{
			if (data == null)
			{
				return 0;
			}

			int i = data.Length;
			int hc = i + 1;

			while (--i >= 0)
			{
				hc *= 257;
				hc ^= data[i];
			}

			return hc;
		}

		public static int GetHashCode(int[][] ints)
		{
			int hc = 0;

			for (int i = 0; i != ints.Length; i++)
			{
				hc = hc * 257 + GetHashCode(ints[i]);
			}

			return hc;
		}

		public static int GetHashCode(int[] data)
		{
			if (data == null)
			{
				return 0;
			}

			int i = data.Length;
			int hc = i + 1;

			while (--i >= 0)
			{
				hc *= 257;
				hc ^= data[i];
			}

			return hc;
		}

		public static int GetHashCode(int[] data, int off, int len)
		{
			if (data == null)
			{
				return 0;
			}

			int i = len;
			int hc = i + 1;

			while (--i >= 0)
			{
				hc *= 257;
				hc ^= data[off + i];
			}

			return hc;
		}

		public static int GetHashCode(long[] data)
		{
			if (data == null)
			{
				return 0;
			}

			int i = data.Length;
			int hc = i + 1;

			while (--i >= 0)
			{
				long di = data[i];
				hc *= 257;
				hc ^= (int)di;
				hc *= 257;
				hc ^= (int)((long)((ulong)di >> 32));
			}

			return hc;
		}

		public static int GetHashCode(long[] data, int off, int len)
		{
			if (data == null)
			{
				return 0;
			}

			int i = len;
			int hc = i + 1;

			while (--i >= 0)
			{
				long di = data[off + i];
				hc *= 257;
				hc ^= (int)di;
				hc *= 257;
				hc ^= (int)((long)((ulong)di >> 32));
			}

			return hc;
		}

		public static int GetHashCode(short[][][] shorts)
		{
			int hc = 0;

			for (int i = 0; i != shorts.Length; i++)
			{
				hc = hc * 257 + GetHashCode(shorts[i]);
			}

			return hc;
		}

		public static int GetHashCode(short[][] shorts)
		{
			int hc = 0;

			for (int i = 0; i != shorts.Length; i++)
			{
				hc = hc * 257 + GetHashCode(shorts[i]);
			}

			return hc;
		}

		public static int GetHashCode(short[] data)
		{
			if (data == null)
			{
				return 0;
			}

			int i = data.Length;
			int hc = i + 1;

			while (--i >= 0)
			{
				hc *= 257;
				hc ^= (data[i] & 0xff);
			}

			return hc;
		}

		public static int GetHashCode(object[] data)
		{
			if (data == null)
			{
				return 0;
			}

			int i = data.Length;
			int hc = i + 1;

			while (--i >= 0)
			{
				hc *= 257;
				hc ^= data[i].GetHashCode();
			}

			return hc;
		}

		public static byte[] clone(byte[] data)
		{
			if (data == null)
			{
				return null;
			}
			byte[] copy = new byte[data.Length];

			JavaSystem.arraycopy(data, 0, copy, 0, data.Length);

			return copy;
		}

		public static char[] clone(char[] data)
		{
			if (data == null)
			{
				return null;
			}
			char[] copy = new char[data.Length];

			JavaSystem.arraycopy(data, 0, copy, 0, data.Length);

			return copy;
		}

		public static byte[] clone(byte[] data, byte[] existing)
		{
			if (data == null)
			{
				return null;
			}
			if ((existing == null) || (existing.Length != data.Length))
			{
				return clone(data);
			}
			JavaSystem.arraycopy(data, 0, existing, 0, existing.Length);
			return existing;
		}

		public static byte[][] clone(byte[][] data)
		{
			if (data == null)
			{
				return null;
			}

			byte[][] copy = new byte[data.Length][];

			for (int i = 0; i != copy.Length; i++)
			{
				copy[i] = clone(data[i]);
			}

			return copy;
		}

		public static byte[][][] clone(byte[][][] data)
		{
			if (data == null)
			{
				return null;
			}

			byte[][][] copy = new byte[data.Length][][];

			for (int i = 0; i != copy.Length; i++)
			{
				copy[i] = clone(data[i]);
			}

			return copy;
		}

		public static int[] clone(int[] data)
		{
			if (data == null)
			{
				return null;
			}
			int[] copy = new int[data.Length];

			JavaSystem.arraycopy(data, 0, copy, 0, data.Length);

			return copy;
		}

		public static long[] clone(long[] data)
		{
			if (data == null)
			{
				return null;
			}
			long[] copy = new long[data.Length];

			JavaSystem.arraycopy(data, 0, copy, 0, data.Length);

			return copy;
		}

		public static long[] clone(long[] data, long[] existing)
		{
			if (data == null)
			{
				return null;
			}
			if ((existing == null) || (existing.Length != data.Length))
			{
				return clone(data);
			}
			JavaSystem.arraycopy(data, 0, existing, 0, existing.Length);
			return existing;
		}

		public static short[] clone(short[] data)
		{
			if (data == null)
			{
				return null;
			}
			short[] copy = new short[data.Length];

			JavaSystem.arraycopy(data, 0, copy, 0, data.Length);

			return copy;
		}

		public static BigInteger[] clone(BigInteger[] data)
		{
			if (data == null)
			{
				return null;
			}
			BigInteger[] copy = new BigInteger[data.Length];

			JavaSystem.arraycopy(data, 0, copy, 0, data.Length);

			return copy;
		}

		public static byte[] copyOf(byte[] data, int newLength)
		{
			byte[] tmp = new byte[newLength];

			if (newLength < data.Length)
			{
				JavaSystem.arraycopy(data, 0, tmp, 0, newLength);
			}
			else
			{
				JavaSystem.arraycopy(data, 0, tmp, 0, data.Length);
			}

			return tmp;
		}

		public static char[] copyOf(char[] data, int newLength)
		{
			char[] tmp = new char[newLength];

			if (newLength < data.Length)
			{
				JavaSystem.arraycopy(data, 0, tmp, 0, newLength);
			}
			else
			{
				JavaSystem.arraycopy(data, 0, tmp, 0, data.Length);
			}

			return tmp;
		}

		public static int[] copyOf(int[] data, int newLength)
		{
			int[] tmp = new int[newLength];

			if (newLength < data.Length)
			{
				JavaSystem.arraycopy(data, 0, tmp, 0, newLength);
			}
			else
			{
				JavaSystem.arraycopy(data, 0, tmp, 0, data.Length);
			}

			return tmp;
		}

		public static long[] copyOf(long[] data, int newLength)
		{
			long[] tmp = new long[newLength];

			if (newLength < data.Length)
			{
				JavaSystem.arraycopy(data, 0, tmp, 0, newLength);
			}
			else
			{
				JavaSystem.arraycopy(data, 0, tmp, 0, data.Length);
			}

			return tmp;
		}

		public static BigInteger[] copyOf(BigInteger[] data, int newLength)
		{
			BigInteger[] tmp = new BigInteger[newLength];

			if (newLength < data.Length)
			{
				JavaSystem.arraycopy(data, 0, tmp, 0, newLength);
			}
			else
			{
				JavaSystem.arraycopy(data, 0, tmp, 0, data.Length);
			}

			return tmp;
		}

		/// <summary>
		/// Make a copy of a range of bytes from the passed in data array. The range can
		/// extend beyond the end of the input array, in which case the return array will
		/// be padded with zeroes.
		/// </summary>
		/// <param name="data"> the array from which the data is to be copied. </param>
		/// <param name="from"> the start index at which the copying should take place. </param>
		/// <param name="to"> the final index of the range (exclusive).
		/// </param>
		/// <returns> a new byte array containing the range given. </returns>
		public static byte[] copyOfRange(byte[] data, int from, int to)
		{
			int newLength = getLength(from, to);

			byte[] tmp = new byte[newLength];

			if (data.Length - from < newLength)
			{
				JavaSystem.arraycopy(data, from, tmp, 0, data.Length - from);
			}
			else
			{
				JavaSystem.arraycopy(data, from, tmp, 0, newLength);
			}

			return tmp;
		}

		public static int[] copyOfRange(int[] data, int from, int to)
		{
			int newLength = getLength(from, to);

			int[] tmp = new int[newLength];

			if (data.Length - from < newLength)
			{
				JavaSystem.arraycopy(data, from, tmp, 0, data.Length - from);
			}
			else
			{
				JavaSystem.arraycopy(data, from, tmp, 0, newLength);
			}

			return tmp;
		}

		public static long[] copyOfRange(long[] data, int from, int to)
		{
			int newLength = getLength(from, to);

			long[] tmp = new long[newLength];

			if (data.Length - from < newLength)
			{
				JavaSystem.arraycopy(data, from, tmp, 0, data.Length - from);
			}
			else
			{
				JavaSystem.arraycopy(data, from, tmp, 0, newLength);
			}

			return tmp;
		}

		public static BigInteger[] copyOfRange(BigInteger[] data, int from, int to)
		{
			int newLength = getLength(from, to);

			BigInteger[] tmp = new BigInteger[newLength];

			if (data.Length - from < newLength)
			{
				JavaSystem.arraycopy(data, from, tmp, 0, data.Length - from);
			}
			else
			{
				JavaSystem.arraycopy(data, from, tmp, 0, newLength);
			}

			return tmp;
		}

		private static int getLength(int from, int to)
		{
			int newLength = to - from;
			if (newLength < 0)
			{
				StringBuffer sb = new StringBuffer(from);
				sb.append(" > ").append(to);
				throw new IllegalArgumentException(sb.ToString());
			}
			return newLength;
		}

		public static byte[] append(byte[] a, byte b)
		{
			if (a == null)
			{
				return new byte[]{b};
			}

			int length = a.Length;
			byte[] result = new byte[length + 1];
			JavaSystem.arraycopy(a, 0, result, 0, length);
			result[length] = b;
			return result;
		}



        public static short[] append(short[] a, short b)
		{
			if (a == null)
			{
				return new short[]{b};
			}

			int length = a.Length;
			short[] result = new short[length + 1];
			JavaSystem.arraycopy(a, 0, result, 0, length);
			result[length] = b;
			return result;
		}

		public static int[] append(int[] a, int b)
		{
			if (a == null)
			{
				return new int[]{b};
			}

			int length = a.Length;
			int[] result = new int[length + 1];
			JavaSystem.arraycopy(a, 0, result, 0, length);
			result[length] = b;
			return result;
		}

		public static string[] append(string[] a, string b)
		{
			if (a == null)
			{
				return new string[]{b};
			}

			int length = a.Length;
			string[] result = new string[length + 1];
			JavaSystem.arraycopy(a, 0, result, 0, length);
			result[length] = b;
			return result;
		}



		public static byte[] concatenate(byte[] a, byte[] b)
		{
			if (a != null && b != null)
			{
				byte[] rv = new byte[a.Length + b.Length];

				JavaSystem.arraycopy(a, 0, rv, 0, a.Length);
				JavaSystem.arraycopy(b, 0, rv, a.Length, b.Length);

				return rv;
			}
			else if (b != null)
			{
				return clone(b);
			}
			else
			{
				return clone(a);
			}
		}

		public static byte[] concatenate(byte[] a, byte[] b, byte[] c)
		{
			if (a != null && b != null && c != null)
			{
				byte[] rv = new byte[a.Length + b.Length + c.Length];

				JavaSystem.arraycopy(a, 0, rv, 0, a.Length);
				JavaSystem.arraycopy(b, 0, rv, a.Length, b.Length);
				JavaSystem.arraycopy(c, 0, rv, a.Length + b.Length, c.Length);

				return rv;
			}
			else if (a == null)
			{
				return concatenate(b, c);
			}
			else if (b == null)
			{
				return concatenate(a, c);
			}
			else
			{
				return concatenate(a, b);
			}
		}

		public static byte[] concatenate(byte[] a, byte[] b, byte[] c, byte[] d)
		{
			if (a != null && b != null && c != null && d != null)
			{
				byte[] rv = new byte[a.Length + b.Length + c.Length + d.Length];

				JavaSystem.arraycopy(a, 0, rv, 0, a.Length);
				JavaSystem.arraycopy(b, 0, rv, a.Length, b.Length);
				JavaSystem.arraycopy(c, 0, rv, a.Length + b.Length, c.Length);
				JavaSystem.arraycopy(d, 0, rv, a.Length + b.Length + c.Length, d.Length);

				return rv;
			}
			else if (d == null)
			{
				return concatenate(a, b, c);
			}
			else if (c == null)
			{
				return concatenate(a, b, d);
			}
			else if (b == null)
			{
				return concatenate(a, c, d);
			}
			else
			{
				return concatenate(b, c, d);
			}
		}

		public static byte[] concatenate(byte[][] arrays)
		{
			int size = 0;
			for (int i = 0; i != arrays.Length; i++)
			{
				size += arrays[i].Length;
			}

			byte[] rv = new byte[size];

			int offSet = 0;
			for (int i = 0; i != arrays.Length; i++)
			{
				JavaSystem.arraycopy(arrays[i], 0, rv, offSet, arrays[i].Length);
				offSet += arrays[i].Length;
			}

			return rv;
		}

		public static int[] concatenate(int[] a, int[] b)
		{
			if (a == null)
			{
				return clone(b);
			}
			if (b == null)
			{
				return clone(a);
			}

			int[] c = new int[a.Length + b.Length];
			JavaSystem.arraycopy(a, 0, c, 0, a.Length);
			JavaSystem.arraycopy(b, 0, c, a.Length, b.Length);
			return c;
		}

		public static byte[] prepend(byte[] a, byte b)
		{
			if (a == null)
			{
				return new byte[]{b};
			}

			int length = a.Length;
			byte[] result = new byte[length + 1];
			JavaSystem.arraycopy(a, 0, result, 1, length);
			result[0] = b;
			return result;
		}

		public static short[] prepend(short[] a, short b)
		{
			if (a == null)
			{
				return new short[]{b};
			}

			int length = a.Length;
			short[] result = new short[length + 1];
			JavaSystem.arraycopy(a, 0, result, 1, length);
			result[0] = b;
			return result;
		}

		public static int[] prepend(int[] a, int b)
		{
			if (a == null)
			{
				return new int[]{b};
			}

			int length = a.Length;
			int[] result = new int[length + 1];
			JavaSystem.arraycopy(a, 0, result, 1, length);
			result[0] = b;
			return result;
		}

		public static byte[] reverse(byte[] a)
		{
			if (a == null)
			{
				return null;
			}

			int p1 = 0, p2 = a.Length;
			byte[] result = new byte[p2];

			while (--p2 >= 0)
			{
				result[p2] = a[p1++];
			}

			return result;
		}

		public static int[] reverse(int[] a)
		{
			if (a == null)
			{
				return null;
			}

			int p1 = 0, p2 = a.Length;
			int[] result = new int[p2];

			while (--p2 >= 0)
			{
				result[p2] = a[p1++];
			}

			return result;
		}

		/// <summary>
		/// Iterator backed by a specific array.
		/// </summary>
		public class Iterator<T> : org.bouncycastle.Port.java.util.Iterator<T>
		{
			internal readonly T[] dataArray;

			internal int position = 0;

			/// <summary>
			/// Base constructor.
			/// <para>
			/// Note: the array is not cloned, changes to it will affect the values returned by next().
			/// </para>
			/// </summary>
			/// <param name="dataArray"> array backing the iterator. </param>
			public Iterator(T[] dataArray)
			{
				this.dataArray = dataArray;
			}

			public virtual bool hasNext()
			{
				return position < dataArray.Length;
			}

			public virtual T next()
			{
				if (position == dataArray.Length)
				{
					throw new NoSuchElementException("Out of elements: " + position);
				}

				return dataArray[position++];
			}

			public virtual void remove()
			{
				throw new UnsupportedOperationException("Cannot remove element from an Array.");
			}
		}

		/// <summary>
		/// Fill input array by zeros
		/// </summary>
		/// <param name="array"> input array </param>
		public static void clear(byte[] array)
		{
			if (array != null)
			{
				for (int i = 0; i < array.Length; i++)
				{
					array[i] = 0;
				}
			}
		}
	}

}