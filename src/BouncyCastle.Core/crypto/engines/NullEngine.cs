using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.engines
{

	/// <summary>
	/// The no-op engine that just copies bytes through, irrespective of whether encrypting and decrypting.
	/// Provided for the sake of completeness.
	/// </summary>
	public class NullEngine : BlockCipher
	{
		private bool initialised;
		protected internal const int DEFAULT_BLOCK_SIZE = 1;
		private readonly int blockSize;

		/// <summary>
		/// Constructs a null engine with a block size of 1 byte.
		/// </summary>
		public NullEngine() : this(DEFAULT_BLOCK_SIZE)
		{
		}

		/// <summary>
		/// Constructs a null engine with a specific block size.
		/// </summary>
		/// <param name="blockSize"> the block size in bytes. </param>
		public NullEngine(int blockSize)
		{
			this.blockSize = blockSize;
		}

		/* (non-Javadoc)
		 * @see org.bouncycastle.crypto.BlockCipher#init(boolean, org.bouncycastle.crypto.CipherParameters)
		 */
		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			// we don't mind any parameters that may come in
			this.initialised = true;
		}

		/* (non-Javadoc)
		 * @see org.bouncycastle.crypto.BlockCipher#getAlgorithmName()
		 */
		public virtual string getAlgorithmName()
		{
			return "Null";
		}

		/* (non-Javadoc)
		 * @see org.bouncycastle.crypto.BlockCipher#getBlockSize()
		 */
		public virtual int getBlockSize()
		{
			return blockSize;
		}

		/* (non-Javadoc)
		 * @see org.bouncycastle.crypto.BlockCipher#processBlock(byte[], int, byte[], int)
		 */
		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if (!initialised)
			{
				throw new IllegalStateException("Null engine not initialised");
			}
			if ((inOff + blockSize) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOff + blockSize) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			for (int i = 0; i < blockSize; ++i)
			{
				@out[outOff + i] = @in[inOff + i];
			}

			return blockSize;
		}

		/* (non-Javadoc)
		 * @see org.bouncycastle.crypto.BlockCipher#reset()
		 */
		public virtual void reset()
		{
			// nothing needs to be done
		}
	}

}