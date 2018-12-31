using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.modes
{
	
	/// <summary>
	/// implements a Output-FeedBack (OFB) mode on top of a simple cipher.
	/// </summary>
	public class OFBBlockCipher : StreamBlockCipher
	{
		private int byteCount;
		private byte[] IV;
		private byte[] ofbV;
		private byte[] ofbOutV;

		private readonly int blockSize;
		private readonly BlockCipher cipher;

		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="cipher"> the block cipher to be used as the basis of the
		/// feedback mode. </param>
		/// <param name="blockSize"> the block size in bits (note: a multiple of 8) </param>
		public OFBBlockCipher(BlockCipher cipher, int blockSize) : base(cipher)
		{

			this.cipher = cipher;
			this.blockSize = blockSize / 8;

			this.IV = new byte[cipher.getBlockSize()];
			this.ofbV = new byte[cipher.getBlockSize()];
			this.ofbOutV = new byte[cipher.getBlockSize()];
		}

		/// <summary>
		/// Initialise the cipher and, possibly, the initialisation vector (IV).
		/// If an IV isn't passed as part of the parameter, the IV will be all zeros.
		/// An IV which is too short is handled in FIPS compliant fashion.
		/// </summary>
		/// <param name="encrypting"> if true the cipher is initialised for
		///  encryption, if false for decryption. </param>
		/// <param name="params"> the key and other data required by the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		public override void init(bool encrypting, CipherParameters @params)
		{
			if (@params is ParametersWithIV)
			{
				ParametersWithIV ivParam = (ParametersWithIV)@params;
				byte[] iv = ivParam.getIV();

				if (iv.Length < IV.Length)
				{
					// prepend the supplied IV with zeros (per FIPS PUB 81)
					JavaSystem.arraycopy(iv, 0, IV, IV.Length - iv.Length, iv.Length);
					for (int i = 0; i < IV.Length - iv.Length; i++)
					{
						IV[i] = 0;
					}
				}
				else
				{
					JavaSystem.arraycopy(iv, 0, IV, 0, IV.Length);
				}

				reset();

				// if null it's an IV changed only.
				if (ivParam.getParameters() != null)
				{
					cipher.init(true, ivParam.getParameters());
				}
			}
			else
			{
				reset();

				// if it's null, key is to be reused.
				if (@params != null)
				{
					cipher.init(true, @params);
				}
			}
		}

		/// <summary>
		/// return the algorithm name and mode.
		/// </summary>
		/// <returns> the name of the underlying algorithm followed by "/OFB"
		/// and the block size in bits </returns>
		public override string getAlgorithmName()
		{
			return cipher.getAlgorithmName() + "/OFB" + (blockSize * 8);
		}


		/// <summary>
		/// return the block size we are operating at (in bytes).
		/// </summary>
		/// <returns> the block size we are operating at (in bytes). </returns>
		public override int getBlockSize()
		{
			return blockSize;
		}

		/// <summary>
		/// Process one block of input from the array in and write it to
		/// the out array.
		/// </summary>
		/// <param name="in"> the array containing the input data. </param>
		/// <param name="inOff"> offset into the in array the data starts at. </param>
		/// <param name="out"> the array the output data will be copied into. </param>
		/// <param name="outOff"> the offset into the out array the output will start at. </param>
		/// <exception cref="DataLengthException"> if there isn't enough data in in, or
		/// space in out. </exception>
		/// <exception cref="IllegalStateException"> if the cipher isn't initialised. </exception>
		/// <returns> the number of bytes processed and produced. </returns>
		public override int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			processBytes(@in, inOff, blockSize, @out, outOff);

			return blockSize;
		}

		/// <summary>
		/// reset the feedback vector back to the IV and reset the underlying
		/// cipher.
		/// </summary>
		public override void reset()
		{
			JavaSystem.arraycopy(IV, 0, ofbV, 0, IV.Length);
			byteCount = 0;

			cipher.reset();
		}

		public override byte calculateByte(byte @in)
		{
			if (byteCount == 0)
			{
				cipher.processBlock(ofbV, 0, ofbOutV, 0);
			}

			byte rv = (byte)(ofbOutV[byteCount++] ^ @in);

			if (byteCount == blockSize)
			{
				byteCount = 0;

				JavaSystem.arraycopy(ofbV, blockSize, ofbV, 0, ofbV.Length - blockSize);
				JavaSystem.arraycopy(ofbOutV, 0, ofbV, ofbV.Length - blockSize, blockSize);
			}

			return rv;
		}
	}

}