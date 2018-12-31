using System.IO;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.util.test
{

	using Hex = org.bouncycastle.util.encoders.Hex;

	/// <summary>
	/// A secure random that returns pre-seeded data to calls of nextBytes() or generateSeed().
	/// </summary>
	public class FixedSecureRandom : SecureRandom
	{
		private static BouncyCastle.Core.Port.BigInteger REGULAR = new BouncyCastle.Core.Port.BigInteger("01020304ffffffff0506070811111111", 16);
		private static BouncyCastle.Core.Port.BigInteger ANDROID = new BouncyCastle.Core.Port.BigInteger("1111111105060708ffffffff01020304", 16);
		private static BouncyCastle.Core.Port.BigInteger CLASSPATH = new BouncyCastle.Core.Port.BigInteger("3020104ffffffff05060708111111", 16);

		private static readonly bool isAndroidStyle;
		private static readonly bool isClasspathStyle;
		private static readonly bool isRegularStyle;

		static FixedSecureRandom()
		{
			BouncyCastle.Core.Port.BigInteger check1 = new BouncyCastle.Core.Port.BigInteger(128, new RandomChecker());
			BouncyCastle.Core.Port.BigInteger check2 = new BouncyCastle.Core.Port.BigInteger(120, new RandomChecker());

			isAndroidStyle = check1.Equals(ANDROID);
			isRegularStyle = check1.Equals(REGULAR);
			isClasspathStyle = check2.Equals(CLASSPATH);
		}

		private byte[] _data;
		private int _index;

		/// <summary>
		/// Base class for sources of fixed "Randomness"
		/// </summary>
		public class Source
		{
			internal byte[] data;

			public Source(byte[] data)
			{
				this.data = data;
			}
		}

		/// <summary>
		/// Data Source - in this case we just expect requests for byte arrays.
		/// </summary>
		public class Data : Source
		{
			public Data(byte[] data) : base(data)
			{
			}
		}

		/// <summary>
		/// BigInteger Source - in this case we expect requests for data that will be used
		/// for BigIntegers. The FixedSecureRandom will attempt to compensate for platform differences here.
		/// </summary>
		public class BigInteger : Source
		{
			public BigInteger(byte[] data) : base(data)
			{
			}

			public BigInteger(int bitLength, byte[] data) : base(expandToBitLength(bitLength, data))
			{
			}

			public BigInteger(string hexData) : this(Hex.decode(hexData))
			{
			}

			public BigInteger(int bitLength, string hexData) : base(expandToBitLength(bitLength, Hex.decode(hexData)))
			{
			}
		}

		public FixedSecureRandom(byte[] value) : this(new Source[] {new Data(value)})
		{
		}

		public FixedSecureRandom(byte[][] values) : this(buildDataArray(values))
		{
		}

		private static Data[] buildDataArray(byte[][] values)
		{
			Data[] res = new Data[values.Length];

			for (int i = 0; i != values.Length; i++)
			{
				res[i] = new Data(values[i]);
			}

			return res;
		}

		public FixedSecureRandom(Source[] sources) : base(null, new DummyProvider()) // to prevent recursion in provider creation
		{

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			if (isRegularStyle)
			{
				if (isClasspathStyle)
				{
					for (int i = 0; i != sources.Length; i++)
					{
						try
						{
							if (sources[i] is BigInteger)
							{
								byte[] data = sources[i].data;
								int len = data.Length - (data.Length % 4);
								for (int w = data.Length - len - 1; w >= 0; w--)
								{
									bOut.write(data[w]);
								}
								for (int w = data.Length - len; w < data.Length; w += 4)
								{
									bOut.write(data, w, 4);
								}
							}
							else
							{
								bOut.write(sources[i].data);
							}
						}
						catch (IOException)
						{
							throw new IllegalArgumentException("can't save value source.");
						}
					}
				}
				else
				{
					for (int i = 0; i != sources.Length; i++)
					{
						try
						{
							bOut.write(sources[i].data);
						}
						catch (IOException)
						{
							throw new IllegalArgumentException("can't save value source.");
						}
					}
				}
			}
			else if (isAndroidStyle)
			{
				for (int i = 0; i != sources.Length; i++)
				{
					try
					{
						if (sources[i] is BigInteger)
						{
							byte[] data = sources[i].data;
							int len = data.Length - (data.Length % 4);
							for (int w = 0; w < len; w += 4)
							{
								bOut.write(data, data.Length - (w + 4), 4);
							}
							if (data.Length - len != 0)
							{
								for (int w = 0; w != 4 - (data.Length - len); w++)
								{
									bOut.write(0);
								}
							}
							for (int w = 0; w != data.Length - len; w++)
							{
								bOut.write(data[len + w]);
							}
						}
						else
						{
							bOut.write(sources[i].data);
						}
					}
					catch (IOException)
					{
						throw new IllegalArgumentException("can't save value source.");
					}
				}
			}
			else
			{
				throw new IllegalStateException("Unrecognized BigInteger implementation");
			}

			_data = bOut.toByteArray();
		}

		public override void nextBytes(byte[] bytes)
		{
			JavaSystem.arraycopy(_data, _index, bytes, 0, bytes.Length);

			_index += bytes.Length;
		}

		public override byte[] generateSeed(int numBytes)
		{
			byte[] bytes = new byte[numBytes];

			this.nextBytes(bytes);

			return bytes;
		}

		//
		// classpath's implementation of SecureRandom doesn't currently go back to nextBytes
		// when next is called. We can't override next as it's a final method.
		//
		public override int nextInt()
		{
			int val = 0;

			val |= nextValue() << 24;
			val |= nextValue() << 16;
			val |= nextValue() << 8;
			val |= nextValue();

			return val;
		}

		//
		// classpath's implementation of SecureRandom doesn't currently go back to nextBytes
		// when next is called. We can't override next as it's a final method.
		//
		public override long nextLong()
		{
			long val = 0;

			val |= (long)nextValue() << 56;
			val |= (long)nextValue() << 48;
			val |= (long)nextValue() << 40;
			val |= (long)nextValue() << 32;
			val |= (long)nextValue() << 24;
			val |= (long)nextValue() << 16;
			val |= (long)nextValue() << 8;
			val |= nextValue();

			return val;
		}

		public virtual bool isExhausted()
		{
			return _index == _data.Length;
		}

		private int nextValue()
		{
			return _data[_index++] & 0xff;
		}

		public class RandomChecker : SecureRandom
		{
			public RandomChecker() : base(null, new DummyProvider()) // to prevent recursion in provider creation
			{
			}

			internal byte[] data = Hex.decode("01020304ffffffff0506070811111111");
			internal int index = 0;

			public override void nextBytes(byte[] bytes)
			{
				JavaSystem.arraycopy(data, index, bytes, 0, bytes.Length);

				index += bytes.Length;
			}
		}

		private static byte[] expandToBitLength(int bitLength, byte[] v)
		{
			if ((bitLength + 7) / 8 > v.Length)
			{
				byte[] tmp = new byte[(bitLength + 7) / 8];

				JavaSystem.arraycopy(v, 0, tmp, tmp.Length - v.Length, v.Length);
				if (isAndroidStyle)
				{
					if (bitLength % 8 != 0)
					{
						int i = Pack.bigEndianToInt(tmp, 0);
						Pack.intToBigEndian(i << (8 - (bitLength % 8)), tmp, 0);
					}
				}

				return tmp;
			}
			else
			{
				if (isAndroidStyle && bitLength < (v.Length * 8))
				{
					if (bitLength % 8 != 0)
					{
						int i = Pack.bigEndianToInt(v, 0);
						Pack.intToBigEndian(i << (8 - (bitLength % 8)), v, 0);
					}
				}
			}

			return v;
		}

		public class DummyProvider 
		{

		}
	}

}