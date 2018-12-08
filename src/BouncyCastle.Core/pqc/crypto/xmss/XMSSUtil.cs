using System;
using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.xmss
{

	using Digest = org.bouncycastle.crypto.Digest;
	using Arrays = org.bouncycastle.util.Arrays;
	using Hex = org.bouncycastle.util.encoders.Hex;

	/// <summary>
	/// Utils for XMSS implementation.
	/// </summary>
	public class XMSSUtil
	{

		/// <summary>
		/// Calculates the logarithm base 2 for a given Integer.
		/// </summary>
		/// <param name="n"> Number. </param>
		/// <returns> Logarithm to base 2 of {@code n}. </returns>
		public static int log2(int n)
		{
			int log = 0;
			while ((n >>= 1) != 0)
			{
				log++;
			}
			return log;
		}

		/// <summary>
		/// Convert int/long to n-byte array.
		/// </summary>
		/// <param name="value">      int/long value. </param>
		/// <param name="sizeInByte"> Size of byte array in byte. </param>
		/// <returns> int/long as big-endian byte array of size {@code sizeInByte}. </returns>
		public static byte[] toBytesBigEndian(long value, int sizeInByte)
		{
			byte[] @out = new byte[sizeInByte];
			for (int i = (sizeInByte - 1); i >= 0; i--)
			{
				@out[i] = (byte)value;
				value = (long)((ulong)value >> 8);
			}
			return @out;
		}

		/*
		 * Copy long to byte array in big-endian at specific offset.
		 */
		public static void longToBigEndian(long value, byte[] @in, int offset)
		{
			if (@in == null)
			{
				throw new NullPointerException("in == null");
			}
			if ((@in.Length - offset) < 8)
			{
				throw new IllegalArgumentException("not enough space in array");
			}
			@in[offset] = unchecked((byte)((value >> 56) & 0xff));
			@in[offset + 1] = unchecked((byte)((value >> 48) & 0xff));
			@in[offset + 2] = unchecked((byte)((value >> 40) & 0xff));
			@in[offset + 3] = unchecked((byte)((value >> 32) & 0xff));
			@in[offset + 4] = unchecked((byte)((value >> 24) & 0xff));
			@in[offset + 5] = unchecked((byte)((value >> 16) & 0xff));
			@in[offset + 6] = unchecked((byte)((value >> 8) & 0xff));
			@in[offset + 7] = unchecked((byte)((value) & 0xff));
		}

		/*
		 * Generic convert from big endian byte array to long.
		 */
		public static long bytesToXBigEndian(byte[] @in, int offset, int size)
		{
			if (@in == null)
			{
				throw new NullPointerException("in == null");
			}
			long res = 0;
			for (int i = offset; i < (offset + size); i++)
			{
				res = (res << 8) | (@in[i] & 0xff);
			}
			return res;
		}

		/// <summary>
		/// Clone a byte array.
		/// </summary>
		/// <param name="in"> byte array. </param>
		/// <returns> Copy of byte array. </returns>
		public static byte[] cloneArray(byte[] @in)
		{
			if (@in == null)
			{
				throw new NullPointerException("in == null");
			}
			byte[] @out = new byte[@in.Length];
			JavaSystem.arraycopy(@in, 0, @out, 0, @in.Length);
			return @out;
		}

		/// <summary>
		/// Clone a 2d byte array.
		/// </summary>
		/// <param name="in"> 2d byte array. </param>
		/// <returns> Copy of 2d byte array. </returns>
		public static byte[][] cloneArray(byte[][] @in)
		{
			if (hasNullPointer(@in))
			{
				throw new NullPointerException("in has null pointers");
			}
			byte[][] @out = new byte[@in.Length][];
			for (int i = 0; i < @in.Length; i++)
			{
				@out[i] = new byte[@in[i].Length];
				JavaSystem.arraycopy(@in[i], 0, @out[i], 0, @in[i].Length);
			}
			return @out;
		}

		/// <summary>
		/// Compares two 2d-byte arrays.
		/// </summary>
		/// <param name="a"> 2d-byte array 1. </param>
		/// <param name="b"> 2d-byte array 2. </param>
		/// <returns> true if all values in 2d-byte array are equal false else. </returns>
		public static bool areEqual(byte[][] a, byte[][] b)
		{
			if (hasNullPointer(a) || hasNullPointer(b))
			{
				throw new NullPointerException("a or b == null");
			}
			for (int i = 0; i < a.Length; i++)
			{
				if (!Arrays.areEqual(a[i], b[i]))
				{
					return false;
				}
			}
			return true;
		}

		/// <summary>
		/// Dump content of 2d byte array.
		/// </summary>
		/// <param name="x"> byte array. </param>
		public static void dumpByteArray(byte[][] x)
		{
			if (hasNullPointer(x))
			{
				throw new NullPointerException("x has null pointers");
			}
			for (int i = 0; i < x.Length; i++)
			{
				JavaSystem.@out.println(Hex.toHexString(x[i]));
			}
		}

		/// <summary>
		/// Checks whether 2d byte array has null pointers.
		/// </summary>
		/// <param name="in"> 2d byte array. </param>
		/// <returns> true if at least one null pointer is found false else. </returns>
		public static bool hasNullPointer(byte[][] @in)
		{
			if (@in == null)
			{
				return true;
			}
			for (int i = 0; i < @in.Length; i++)
			{
				if (@in[i] == null)
				{
					return true;
				}
			}
			return false;
		}

		/// <summary>
		/// Copy src byte array to dst byte array at offset.
		/// </summary>
		/// <param name="dst">    Destination. </param>
		/// <param name="src">    Source. </param>
		/// <param name="offset"> Destination offset. </param>
		public static void copyBytesAtOffset(byte[] dst, byte[] src, int offset)
		{
			if (dst == null)
			{
				throw new NullPointerException("dst == null");
			}
			if (src == null)
			{
				throw new NullPointerException("src == null");
			}
			if (offset < 0)
			{
				throw new IllegalArgumentException("offset hast to be >= 0");
			}
			if ((src.Length + offset) > dst.Length)
			{
				throw new IllegalArgumentException("src length + offset must not be greater than size of destination");
			}
			for (int i = 0; i < src.Length; i++)
			{
				dst[offset + i] = src[i];
			}
		}

		/// <summary>
		/// Copy length bytes at position offset from src.
		/// </summary>
		/// <param name="src">    Source byte array. </param>
		/// <param name="offset"> Offset in source byte array. </param>
		/// <param name="length"> Length of bytes to copy. </param>
		/// <returns> New byte array. </returns>
		public static byte[] extractBytesAtOffset(byte[] src, int offset, int length)
		{
			if (src == null)
			{
				throw new NullPointerException("src == null");
			}
			if (offset < 0)
			{
				throw new IllegalArgumentException("offset hast to be >= 0");
			}
			if (length < 0)
			{
				throw new IllegalArgumentException("length hast to be >= 0");
			}
			if ((offset + length) > src.Length)
			{
				throw new IllegalArgumentException("offset + length must not be greater then size of source array");
			}
			byte[] @out = new byte[length];
			for (int i = 0; i < @out.Length; i++)
			{
				@out[i] = src[offset + i];
			}
			return @out;
		}

		/// <summary>
		/// Check whether an index is valid or not.
		/// </summary>
		/// <param name="height"> Height of binary tree. </param>
		/// <param name="index">  Index to validate. </param>
		/// <returns> true if index is valid false else. </returns>
		public static bool isIndexValid(int height, long index)
		{
			if (index < 0)
			{
				throw new IllegalStateException("index must not be negative");
			}
			return index < (1L << height);
		}

		/// <summary>
		/// Determine digest size of digest.
		/// </summary>
		/// <param name="digest"> Digest. </param>
		/// <returns> Digest size. </returns>
		public static int getDigestSize(Digest digest)
		{
			if (digest == null)
			{
				throw new NullPointerException("digest == null");
			}
			string algorithmName = digest.getAlgorithmName();
			if (algorithmName.Equals("SHAKE128"))
			{
				return 32;
			}
			if (algorithmName.Equals("SHAKE256"))
			{
				return 64;
			}
			return digest.getDigestSize();
		}

		public static long getTreeIndex(long index, int xmssTreeHeight)
		{
			return index >> xmssTreeHeight;
		}

		public static int getLeafIndex(long index, int xmssTreeHeight)
		{
			return (int)(index & ((1L << xmssTreeHeight) - 1L));
		}

		public static byte[] serialize(object obj)
		{
			ByteArrayOutputStream @out = new ByteArrayOutputStream();
			ObjectOutputStream oos = new ObjectOutputStream(@out);
			oos.writeObject(obj);
			oos.flush();
			return @out.toByteArray();
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public static Object deserialize(byte[] data, final Class clazz) throws java.io.IOException, ClassNotFoundException
		public static object deserialize(byte[] data, Class clazz)
		{
			ByteArrayInputStream @in = new ByteArrayInputStream(data);
			ObjectInputStream @is = new CheckingStream(clazz, @in);

			object obj = @is.readObject();

			if (@is.available() != 0)
			{
				throw new IOException("unexpected data found at end of ObjectInputStream");
			}
			// you'd hope this would always succeed!
			if (clazz.isInstance(obj))
			{
				return obj;
			}
			else
			{
				throw new IOException("unexpected class found in ObjectInputStream");
			}
		}

		public static int calculateTau(int index, int height)
		{
			int tau = 0;
			for (int i = 0; i < height; i++)
			{
				if (((index >> i) & 1) == 0)
				{
					tau = i;
					break;
				}
			}
			return tau;
		}

		public static bool isNewBDSInitNeeded(long globalIndex, int xmssHeight, int layer)
		{
			if (globalIndex == 0)
			{
				return false;
			}
			return (globalIndex % (long)Math.pow((1 << xmssHeight), layer + 1) == 0) ? true : false;
		}

		public static bool isNewAuthenticationPathNeeded(long globalIndex, int xmssHeight, int layer)
		{
			if (globalIndex == 0)
			{
				return false;
			}
			return ((globalIndex + 1) % (long)Math.pow((1 << xmssHeight), layer) == 0) ? true : false;
		}

		public class CheckingStream : ObjectInputStream
		{
			internal static readonly Set components = new HashSet();

			static CheckingStream()
			{
				components.add("java.util.TreeMap");
				components.add("java.lang.Integer");
				components.add("java.lang.Number");
				components.add("org.bouncycastle.pqc.crypto.xmss.BDS");
				components.add("java.util.ArrayList");
				components.add("org.bouncycastle.pqc.crypto.xmss.XMSSNode");
				components.add("[B");
				components.add("java.util.LinkedList");
				components.add("java.util.Stack");
				components.add("java.util.Vector");
				components.add("[Ljava.lang.Object;");
				components.add("org.bouncycastle.pqc.crypto.xmss.BDSTreeHash");
			}

			internal readonly Class mainClass;
			internal bool found = false;

			public CheckingStream(Class mainClass, InputStream @in) : base(@in)
			{

				this.mainClass = mainClass;
			}

			public virtual Class resolveClass(ObjectStreamClass desc)
			{
				if (!found)
				{
					if (!desc.getName().Equals(mainClass.getName()))
					{
						throw new InvalidClassException("unexpected class: ", desc.getName());
					}
					else
					{
						found = true;
					}
				}
				else
				{
					if (!components.contains(desc.getName()))
					{
						throw new InvalidClassException("unexpected class: ", desc.getName());
					}
				}
				return base.resolveClass(desc);
			}
		}
	}

}