namespace org.bouncycastle.crypto
{
	/// <summary>
	/// A parent class for block cipher modes that do not require block aligned data to be processed, but can function in
	/// a streaming mode.
	/// </summary>
	public abstract class StreamBlockCipher : BlockCipher, StreamCipher
	{
		public abstract void reset();
		public abstract int processBlock(byte[] @in, int inOff, byte[] @out, int outOff);
		public abstract int getBlockSize();
		public abstract string getAlgorithmName();
		public abstract void init(bool forEncryption, CipherParameters @params);
		private readonly BlockCipher cipher;

		public StreamBlockCipher(BlockCipher cipher)
		{
			this.cipher = cipher;
		}

		/// <summary>
		/// return the underlying block cipher that we are wrapping.
		/// </summary>
		/// <returns> the underlying block cipher that we are wrapping. </returns>
		public virtual BlockCipher getUnderlyingCipher()
		{
			return cipher;
		}

		public byte returnByte(byte @in)
		{
			return calculateByte(@in);
		}

		public virtual int processBytes(byte[] @in, int inOff, int len, byte[] @out, int outOff)
		{
			if (inOff + len > @in.Length)
			{
				throw new DataLengthException("input buffer too small");
			}
			if (outOff + len > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			int inStart = inOff;
			int inEnd = inOff + len;
			int outStart = outOff;

			while (inStart < inEnd)
			{
				 @out[outStart++] = calculateByte(@in[inStart++]);
			}

			return len;
		}

		public abstract byte calculateByte(byte b);
	}
}