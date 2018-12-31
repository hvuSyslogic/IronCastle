using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.modes
{
		
	/// <summary>
	/// implements a Cipher-FeedBack (CFB) mode on top of a simple cipher.
	/// </summary>
	public class CFBBlockCipher : StreamBlockCipher
	{
		private byte[] IV;
		private byte[] cfbV;
		private byte[] cfbOutV;
		private byte[] inBuf;

		private int blockSize;
		private BlockCipher cipher = null;
		private bool encrypting;
		private int byteCount;

		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="cipher"> the block cipher to be used as the basis of the
		/// feedback mode. </param>
		/// <param name="bitBlockSize"> the block size in bits (note: a multiple of 8) </param>
		public CFBBlockCipher(BlockCipher cipher, int bitBlockSize) : base(cipher)
		{

			this.cipher = cipher;
			this.blockSize = bitBlockSize / 8;

			this.IV = new byte[cipher.getBlockSize()];
			this.cfbV = new byte[cipher.getBlockSize()];
			this.cfbOutV = new byte[cipher.getBlockSize()];
			this.inBuf = new byte[blockSize];
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
			this.encrypting = encrypting;

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
		/// <returns> the name of the underlying algorithm followed by "/CFB"
		/// and the block size in bits. </returns>
		public override string getAlgorithmName()
		{
			return cipher.getAlgorithmName() + "/CFB" + (blockSize * 8);
		}

		public override byte calculateByte(byte @in)
		{
			return (encrypting) ? encryptByte(@in) : decryptByte(@in);
		}

		private byte encryptByte(byte @in)
		{
			if (byteCount == 0)
			{
				cipher.processBlock(cfbV, 0, cfbOutV, 0);
			}

			byte rv = (byte)(cfbOutV[byteCount] ^ @in);
			inBuf[byteCount++] = rv;

			if (byteCount == blockSize)
			{
				byteCount = 0;

				JavaSystem.arraycopy(cfbV, blockSize, cfbV, 0, cfbV.Length - blockSize);
				JavaSystem.arraycopy(inBuf, 0, cfbV, cfbV.Length - blockSize, blockSize);
			}

			return rv;
		}

		private byte decryptByte(byte @in)
		{
			if (byteCount == 0)
			{
				cipher.processBlock(cfbV, 0, cfbOutV, 0);
			}

			inBuf[byteCount] = @in;
			byte rv = (byte)(cfbOutV[byteCount++] ^ @in);

			if (byteCount == blockSize)
			{
				byteCount = 0;

				JavaSystem.arraycopy(cfbV, blockSize, cfbV, 0, cfbV.Length - blockSize);
				JavaSystem.arraycopy(inBuf, 0, cfbV, cfbV.Length - blockSize, blockSize);
			}

			return rv;
		}

		/// <summary>
		/// return the block size we are operating at.
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
		/// Do the appropriate processing for CFB mode encryption.
		/// </summary>
		/// <param name="in"> the array containing the data to be encrypted. </param>
		/// <param name="inOff"> offset into the in array the data starts at. </param>
		/// <param name="out"> the array the encrypted data will be copied into. </param>
		/// <param name="outOff"> the offset into the out array the output will start at. </param>
		/// <exception cref="DataLengthException"> if there isn't enough data in in, or
		/// space in out. </exception>
		/// <exception cref="IllegalStateException"> if the cipher isn't initialised. </exception>
		/// <returns> the number of bytes processed and produced. </returns>
		public virtual int encryptBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			processBytes(@in, inOff, blockSize, @out, outOff);

			return blockSize;
		}

		/// <summary>
		/// Do the appropriate processing for CFB mode decryption.
		/// </summary>
		/// <param name="in"> the array containing the data to be decrypted. </param>
		/// <param name="inOff"> offset into the in array the data starts at. </param>
		/// <param name="out"> the array the encrypted data will be copied into. </param>
		/// <param name="outOff"> the offset into the out array the output will start at. </param>
		/// <exception cref="DataLengthException"> if there isn't enough data in in, or
		/// space in out. </exception>
		/// <exception cref="IllegalStateException"> if the cipher isn't initialised. </exception>
		/// <returns> the number of bytes processed and produced. </returns>
		public virtual int decryptBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			processBytes(@in, inOff, blockSize, @out, outOff);

			return blockSize;
		}

		/// <summary>
		/// Return the current state of the initialisation vector.
		/// </summary>
		/// <returns> current IV </returns>
		public virtual byte[] getCurrentIV()
		{
			return Arrays.clone(cfbV);
		}

		/// <summary>
		/// reset the chaining vector back to the IV and reset the underlying
		/// cipher.
		/// </summary>
		public override void reset()
		{
			JavaSystem.arraycopy(IV, 0, cfbV, 0, IV.Length);
			Arrays.fill(inBuf, 0);
			byteCount = 0;

			cipher.reset();
		}
	}

}