﻿using System.IO;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.prng
{

	/// <summary>
	/// A secure random that returns pre-seeded data to calls of nextBytes() or generateSeed().
	/// </summary>
	public class FixedSecureRandom : SecureRandom
	{
		private byte[] _data;

		private int _index;
		private int _intPad;

		public FixedSecureRandom(byte[] value) : this(false, new byte[][] {value})
		{
		}

		public FixedSecureRandom(byte[][] values) : this(false, values)
		{
		}

		/// <summary>
		/// Pad the data on integer boundaries. This is necessary for the classpath project's BigInteger
		/// implementation.
		/// </summary>
		public FixedSecureRandom(bool intPad, byte[] value) : this(intPad, new byte[][] {value})
		{
		}

		/// <summary>
		/// Pad the data on integer boundaries. This is necessary for the classpath project's BigInteger
		/// implementation.
		/// </summary>
		public FixedSecureRandom(bool intPad, byte[][] values)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();

			for (int i = 0; i != values.Length; i++)
			{
				try
				{
					bOut.write(values[i]);
				}
				catch (IOException)
				{
					throw new IllegalArgumentException("can't save value array.");
				}
			}

			_data = bOut.toByteArray();

			if (intPad)
			{
				_intPad = _data.Length % 4;
			}
		}

		public virtual void nextBytes(byte[] bytes)
		{
			JavaSystem.arraycopy(_data, _index, bytes, 0, bytes.Length);

			_index += bytes.Length;
		}

		public virtual byte[] generateSeed(int numBytes)
		{
			byte[] bytes = new byte[numBytes];

			this.nextBytes(bytes);

			return bytes;
		}

		//
		// classpath's implementation of SecureRandom doesn't currently go back to nextBytes
		// when next is called. We can't override next as it's a final method.
		//
		public virtual int nextInt()
		{
			int val = 0;

			val |= nextValue() << 24;
			val |= nextValue() << 16;

			if (_intPad == 2)
			{
				_intPad--;
			}
			else
			{
				val |= nextValue() << 8;
			}

			if (_intPad == 1)
			{
				_intPad--;
			}
			else
			{
				val |= nextValue();
			}

			return val;
		}

		//
		// classpath's implementation of SecureRandom doesn't currently go back to nextBytes
		// when next is called. We can't override next as it's a final method.
		//
		public virtual long nextLong()
		{
			long val = 0;

			val |= (long)nextValue() << 56;
			val |= (long)nextValue() << 48;
			val |= (long)nextValue() << 40;
			val |= (long)nextValue() << 32;
			val |= (long)nextValue() << 24;
			val |= (long)nextValue() << 16;
			val |= (long)nextValue() << 8;
			val |= (long)nextValue();

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
	}

}