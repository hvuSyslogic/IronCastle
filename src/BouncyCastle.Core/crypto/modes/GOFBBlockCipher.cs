using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.modes
{
	
	/// <summary>
	/// implements the GOST 28147 OFB counter mode (GCTR).
	/// </summary>
	public class GOFBBlockCipher : StreamBlockCipher
	{
		private byte[] IV;
		private byte[] ofbV;
		private byte[] ofbOutV;
		private int byteCount;

		private readonly int blockSize;
		private readonly BlockCipher cipher;

		internal bool firstStep = true;
		internal int N3;
		internal int N4;
		internal const int C1 = 16843012; //00000001000000010000000100000100
		internal const int C2 = 16843009; //00000001000000010000000100000001


		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="cipher"> the block cipher to be used as the basis of the
		/// counter mode (must have a 64 bit block size). </param>
		public GOFBBlockCipher(BlockCipher cipher) : base(cipher)
		{

			this.cipher = cipher;
			this.blockSize = cipher.getBlockSize();

			if (blockSize != 8)
			{
				throw new IllegalArgumentException("GCTR only for 64 bit block ciphers");
			}

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
			firstStep = true;
			N3 = 0;
			N4 = 0;

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

				// if params is null we reuse the current working key.
				if (ivParam.getParameters() != null)
				{
					cipher.init(true, ivParam.getParameters());
				}
			}
			else
			{
				reset();

				// if params is null we reuse the current working key.
				if (@params != null)
				{
					cipher.init(true, @params);
				}
			}
		}

		/// <summary>
		/// return the algorithm name and mode.
		/// </summary>
		/// <returns> the name of the underlying algorithm followed by "/GCTR"
		/// and the block size in bits </returns>
		public override string getAlgorithmName()
		{
			return cipher.getAlgorithmName() + "/GCTR";
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
			firstStep = true;
			N3 = 0;
			N4 = 0;
			JavaSystem.arraycopy(IV, 0, ofbV, 0, IV.Length);
			byteCount = 0;
			cipher.reset();
		}

		//array of bytes to type int
		private int bytesToint(byte[] @in, int inOff)
		{
			return ((@in[inOff + 3] << 24) & unchecked((int)0xff000000)) + ((@in[inOff + 2] << 16) & 0xff0000) + ((@in[inOff + 1] << 8) & 0xff00) + (@in[inOff] & 0xff);
		}

		//int to array of bytes
		private void intTobytes(int num, byte[] @out, int outOff)
		{
				@out[outOff + 3] = (byte)((int)((uint)num >> 24));
				@out[outOff + 2] = (byte)((int)((uint)num >> 16));
				@out[outOff + 1] = (byte)((int)((uint)num >> 8));
				@out[outOff] = (byte)num;
		}

		public override byte calculateByte(byte b)
		{
			if (byteCount == 0)
			{
				if (firstStep)
				{
					firstStep = false;
					cipher.processBlock(ofbV, 0, ofbOutV, 0);
					N3 = bytesToint(ofbOutV, 0);
					N4 = bytesToint(ofbOutV, 4);
				}
				N3 += C2;
				N4 += C1;
				if (N4 < C1) // addition is mod (2**32 - 1)
				{
					if (N4 > 0)
					{
						N4++;
					}
				}
				intTobytes(N3, ofbV, 0);
				intTobytes(N4, ofbV, 4);

				cipher.processBlock(ofbV, 0, ofbOutV, 0);
			}

			byte rv = (byte)(ofbOutV[byteCount++] ^ b);

			if (byteCount == blockSize)
			{
				byteCount = 0;

				//
				// change over the input block.
				//
				JavaSystem.arraycopy(ofbV, blockSize, ofbV, 0, ofbV.Length - blockSize);
				JavaSystem.arraycopy(ofbOutV, 0, ofbV, ofbV.Length - blockSize, blockSize);
			}

			return rv;
		}
	}

}