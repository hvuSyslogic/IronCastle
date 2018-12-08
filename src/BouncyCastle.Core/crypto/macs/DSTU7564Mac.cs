using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.macs
{
	using DSTU7564Digest = org.bouncycastle.crypto.digests.DSTU7564Digest;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Pack = org.bouncycastle.util.Pack;

	/// <summary>
	/// Implementation of DSTU7564 MAC mode
	/// </summary>
	public class DSTU7564Mac : Mac
	{
		private const int BITS_IN_BYTE = 8;

		private DSTU7564Digest engine;

		private int macSize;

		private byte[] paddedKey;
		private byte[] invertedKey;

		private long inputLength;

		public DSTU7564Mac(int macBitSize)
		{
			/* Mac size can be only 256 / 384 / 512. Same as hash size for DSTU7654Digest */
			this.engine = new DSTU7564Digest(macBitSize);
			this.macSize = macBitSize / BITS_IN_BYTE;

			this.paddedKey = null;
			this.invertedKey = null;
		}

		public virtual void init(CipherParameters @params)
		{
			if (@params is KeyParameter)
			{
				byte[] key = ((KeyParameter)@params).getKey();

				invertedKey = new byte[key.Length];

				paddedKey = padKey(key);

				for (int byteIndex = 0; byteIndex < invertedKey.Length; byteIndex++)
				{
					invertedKey[byteIndex] = (byte)(key[byteIndex] ^ unchecked((byte)0xFF));
				}
			}
			else
			{
				throw new IllegalArgumentException("Bad parameter passed");
			}

			engine.update(paddedKey, 0, paddedKey.Length);
		}

		public virtual string getAlgorithmName()
		{
			return "DSTU7564Mac";
		}

		public virtual int getMacSize()
		{
			return macSize;
		}

		public virtual void update(byte @in)
		{
			engine.update(@in);
			inputLength++;
		}

		public virtual void update(byte[] @in, int inOff, int len)
		{
			if (@in.Length - inOff < len)
			{
				throw new DataLengthException("Input buffer too short");
			}

			if (paddedKey == null)
			{
				throw new IllegalStateException(getAlgorithmName() + " not initialised");
			}

			engine.update(@in, inOff, len);
			inputLength += len;
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			if (paddedKey == null)
			{
				throw new IllegalStateException(getAlgorithmName() + " not initialised");
			}
			if (@out.Length - outOff < macSize)
			{
				throw new OutputLengthException("Output buffer too short");
			}

			pad();

			engine.update(invertedKey, 0, invertedKey.Length);

			inputLength = 0;

			return engine.doFinal(@out, outOff);
		}

		public virtual void reset()
		{
			inputLength = 0;
			engine.reset();
			if (paddedKey != null)
			{
				engine.update(paddedKey, 0, paddedKey.Length);
			}
		}

		private void pad()
		{
			int extra = engine.getByteLength() - (int)(inputLength % engine.getByteLength());
			if (extra < 13) // terminator byte + 96 bits of length
			{
				extra += engine.getByteLength();
			}

			byte[] padded = new byte[extra];

			padded[0] = unchecked((byte)0x80); // Defined in standard;

			// Defined in standard;
			Pack.longToLittleEndian(inputLength * BITS_IN_BYTE, padded, padded.Length - 12);

			engine.update(padded, 0, padded.Length);
		}

		private byte[] padKey(byte[] @in)
		{
			int paddedLen = ((@in.Length + engine.getByteLength() - 1) / engine.getByteLength()) * engine.getByteLength();

			int extra = engine.getByteLength() - (int)(@in.Length % engine.getByteLength());
			if (extra < 13) // terminator byte + 96 bits of length
			{
				paddedLen += engine.getByteLength();
			}

			byte[] padded = new byte[paddedLen];

			JavaSystem.arraycopy(@in, 0, padded, 0, @in.Length);

			padded[@in.Length] = unchecked((byte)0x80); // Defined in standard;
			Pack.intToLittleEndian(@in.Length * BITS_IN_BYTE, padded, padded.Length - 12); // Defined in standard;

			return padded;
		}
	}

}