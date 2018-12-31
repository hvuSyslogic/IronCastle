using System;
using org.bouncycastle.Port;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.digests
{
		
	/// <summary>
	/// base implementation of MD4 family style digest as outlined in
	/// "Handbook of Applied Cryptography", pages 344 - 347.
	/// </summary>
	public abstract class GeneralDigest : ExtendedDigest, Memoable
	{
		public abstract void reset(Memoable other);
		public abstract Memoable copy();
		public abstract int doFinal(byte[] @out, int outOff);
		public abstract int getDigestSize();
		public abstract string getAlgorithmName();
		private const int BYTE_LENGTH = 64;

		private readonly byte[] xBuf = new byte[4];
		private int xBufOff;

		private long byteCount;

		/// <summary>
		/// Standard constructor
		/// </summary>
		public GeneralDigest()
		{
			xBufOff = 0;
		}

		/// <summary>
		/// Copy constructor.  We are using copy constructors in place
		/// of the Object.clone() interface as this interface is not
		/// supported by J2ME.
		/// </summary>
		public GeneralDigest(GeneralDigest t)
		{
			copyIn(t);
		}

		public GeneralDigest(byte[] encodedState)
		{
			JavaSystem.arraycopy(encodedState, 0, xBuf, 0, xBuf.Length);
			xBufOff = Pack.bigEndianToInt(encodedState, 4);
			byteCount = Pack.bigEndianToLong(encodedState, 8);
		}

		public virtual void copyIn(GeneralDigest t)
		{
			JavaSystem.arraycopy(t.xBuf, 0, xBuf, 0, t.xBuf.Length);

			xBufOff = t.xBufOff;
			byteCount = t.byteCount;
		}

		public virtual void update(byte @in)
		{
			xBuf[xBufOff++] = @in;

			if (xBufOff == xBuf.Length)
			{
				processWord(xBuf, 0);
				xBufOff = 0;
			}

			byteCount++;
		}

		public virtual void update(byte[] @in, int inOff, int len)
		{
			len = Math.Max(0, len);

			//
			// fill the current word
			//
			int i = 0;
			if (xBufOff != 0)
			{
				while (i < len)
				{
					xBuf[xBufOff++] = @in[inOff + i++];
					if (xBufOff == 4)
					{
						processWord(xBuf, 0);
						xBufOff = 0;
						break;
					}
				}
			}

			//
			// process whole words.
			//
			int limit = ((len - i) & ~3) + i;
			for (; i < limit; i += 4)
			{
				processWord(@in, inOff + i);
			}

			//
			// load in the remainder.
			//
			while (i < len)
			{
				xBuf[xBufOff++] = @in[inOff + i++];
			}

			byteCount += len;
		}

		public virtual void finish()
		{
			long bitLength = (byteCount << 3);

			//
			// add the pad bytes.
			//
			update(unchecked(128));

			while (xBufOff != 0)
			{
				update(0);
			}

			processLength(bitLength);

			processBlock();
		}

		public virtual void reset()
		{
			byteCount = 0;

			xBufOff = 0;
			for (int i = 0; i < xBuf.Length; i++)
			{
				xBuf[i] = 0;
			}
		}

		public virtual void populateState(byte[] state)
		{
			JavaSystem.arraycopy(xBuf, 0, state, 0, xBufOff);
			Pack.intToBigEndian(xBufOff, state, 4);
			Pack.longToBigEndian(byteCount, state, 8);
		}

		public virtual int getByteLength()
		{
			return BYTE_LENGTH;
		}

		public abstract void processWord(byte[] @in, int inOff);

		public abstract void processLength(long bitLength);

		public abstract void processBlock();
	}

}