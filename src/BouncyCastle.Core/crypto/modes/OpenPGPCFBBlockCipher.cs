using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.modes
{

	/// <summary>
	/// Implements OpenPGP's rather strange version of Cipher-FeedBack (CFB) mode
	/// on top of a simple cipher. This class assumes the IV has been prepended
	/// to the data stream already, and just accomodates the reset after
	/// (blockSize + 2) bytes have been read.
	/// <para>
	/// For further info see <a href="http://www.ietf.org/rfc/rfc2440.html">RFC 2440</a>.
	/// </para>
	/// </summary>
	public class OpenPGPCFBBlockCipher : BlockCipher
	{
		private byte[] IV;
		private byte[] FR;
		private byte[] FRE;

		private BlockCipher cipher;

		private int count;
		private int blockSize;
		private bool forEncryption;

		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="cipher"> the block cipher to be used as the basis of the
		/// feedback mode. </param>
		public OpenPGPCFBBlockCipher(BlockCipher cipher)
		{
			this.cipher = cipher;

			this.blockSize = cipher.getBlockSize();
			this.IV = new byte[blockSize];
			this.FR = new byte[blockSize];
			this.FRE = new byte[blockSize];
		}

		/// <summary>
		/// return the underlying block cipher that we are wrapping.
		/// </summary>
		/// <returns> the underlying block cipher that we are wrapping. </returns>
		public virtual BlockCipher getUnderlyingCipher()
		{
			return cipher;
		}

		/// <summary>
		/// return the algorithm name and mode.
		/// </summary>
		/// <returns> the name of the underlying algorithm followed by "/OpenPGPCFB"
		/// and the block size in bits. </returns>
		public virtual string getAlgorithmName()
		{
			return cipher.getAlgorithmName() + "/OpenPGPCFB";
		}

		/// <summary>
		/// return the block size we are operating at.
		/// </summary>
		/// <returns> the block size we are operating at (in bytes). </returns>
		public virtual int getBlockSize()
		{
			return cipher.getBlockSize();
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
		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			return (forEncryption) ? encryptBlock(@in, inOff, @out, outOff) : decryptBlock(@in, inOff, @out, outOff);
		}

		/// <summary>
		/// reset the chaining vector back to the IV and reset the underlying
		/// cipher.
		/// </summary>
		public virtual void reset()
		{
			count = 0;

			JavaSystem.arraycopy(IV, 0, FR, 0, FR.Length);

			cipher.reset();
		}

		/// <summary>
		/// Initialise the cipher and, possibly, the initialisation vector (IV).
		/// If an IV isn't passed as part of the parameter, the IV will be all zeros.
		/// An IV which is too short is handled in FIPS compliant fashion.
		/// </summary>
		/// <param name="forEncryption"> if true the cipher is initialised for
		///  encryption, if false for decryption. </param>
		/// <param name="params"> the key and other data required by the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			this.forEncryption = forEncryption;

			reset();

			cipher.init(true, @params);
		}

		/// <summary>
		/// Encrypt one byte of data according to CFB mode. </summary>
		/// <param name="data"> the byte to encrypt </param>
		/// <param name="blockOff"> offset in the current block </param>
		/// <returns> the encrypted byte </returns>
		private byte encryptByte(byte data, int blockOff)
		{
			return (byte)(FRE[blockOff] ^ data);
		}

		/// <summary>
		/// Do the appropriate processing for CFB IV mode encryption.
		/// </summary>
		/// <param name="in"> the array containing the data to be encrypted. </param>
		/// <param name="inOff"> offset into the in array the data starts at. </param>
		/// <param name="out"> the array the encrypted data will be copied into. </param>
		/// <param name="outOff"> the offset into the out array the output will start at. </param>
		/// <exception cref="DataLengthException"> if there isn't enough data in in, or
		/// space in out. </exception>
		/// <exception cref="IllegalStateException"> if the cipher isn't initialised. </exception>
		/// <returns> the number of bytes processed and produced. </returns>
		private int encryptBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if ((inOff + blockSize) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}
			if ((outOff + blockSize) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			if (count > blockSize)
			{
				FR[blockSize - 2] = @out[outOff] = encryptByte(@in[inOff], blockSize - 2);
				FR[blockSize - 1] = @out[outOff + 1] = encryptByte(@in[inOff + 1], blockSize - 1);

				cipher.processBlock(FR, 0, FRE, 0);

				for (int n = 2; n < blockSize; n++)
				{
					FR[n - 2] = @out[outOff + n] = encryptByte(@in[inOff + n], n - 2);
				}
			}
			else if (count == 0)
			{
				cipher.processBlock(FR, 0, FRE, 0);

				for (int n = 0; n < blockSize; n++)
				{
					FR[n] = @out[outOff + n] = encryptByte(@in[inOff + n], n);
				}

				count += blockSize;
			}
			else if (count == blockSize)
			{
				cipher.processBlock(FR, 0, FRE, 0);

				@out[outOff] = encryptByte(@in[inOff], 0);
				@out[outOff + 1] = encryptByte(@in[inOff + 1], 1);

				//
				// do reset
				//
				JavaSystem.arraycopy(FR, 2, FR, 0, blockSize - 2);
				JavaSystem.arraycopy(@out, outOff, FR, blockSize - 2, 2);

				cipher.processBlock(FR, 0, FRE, 0);

				for (int n = 2; n < blockSize; n++)
				{
					FR[n - 2] = @out[outOff + n] = encryptByte(@in[inOff + n], n - 2);
				}

				count += blockSize;
			}

			return blockSize;
		}

		/// <summary>
		/// Do the appropriate processing for CFB IV mode decryption.
		/// </summary>
		/// <param name="in"> the array containing the data to be decrypted. </param>
		/// <param name="inOff"> offset into the in array the data starts at. </param>
		/// <param name="out"> the array the encrypted data will be copied into. </param>
		/// <param name="outOff"> the offset into the out array the output will start at. </param>
		/// <exception cref="DataLengthException"> if there isn't enough data in in, or
		/// space in out. </exception>
		/// <exception cref="IllegalStateException"> if the cipher isn't initialised. </exception>
		/// <returns> the number of bytes processed and produced. </returns>
		private int decryptBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if ((inOff + blockSize) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}
			if ((outOff + blockSize) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			if (count > blockSize)
			{
				byte inVal = @in[inOff];
				FR[blockSize - 2] = inVal;
				@out[outOff] = encryptByte(inVal, blockSize - 2);

				inVal = @in[inOff + 1];
				FR[blockSize - 1] = inVal;
				@out[outOff + 1] = encryptByte(inVal, blockSize - 1);

				cipher.processBlock(FR, 0, FRE, 0);

				for (int n = 2; n < blockSize; n++)
				{
					inVal = @in[inOff + n];
					FR[n - 2] = inVal;
					@out[outOff + n] = encryptByte(inVal, n - 2);
				}
			}
			else if (count == 0)
			{
				cipher.processBlock(FR, 0, FRE, 0);

				for (int n = 0; n < blockSize; n++)
				{
					FR[n] = @in[inOff + n];
					@out[n] = encryptByte(@in[inOff + n], n);
				}

				count += blockSize;
			}
			else if (count == blockSize)
			{
				cipher.processBlock(FR, 0, FRE, 0);

				byte inVal1 = @in[inOff];
				byte inVal2 = @in[inOff + 1];
				@out[outOff] = encryptByte(inVal1, 0);
				@out[outOff + 1] = encryptByte(inVal2, 1);

				JavaSystem.arraycopy(FR, 2, FR, 0, blockSize - 2);

				FR[blockSize - 2] = inVal1;
				FR[blockSize - 1] = inVal2;

				cipher.processBlock(FR, 0, FRE, 0);

				for (int n = 2; n < blockSize; n++)
				{
					byte inVal = @in[inOff + n];
					FR[n - 2] = inVal;
					@out[outOff + n] = encryptByte(inVal, n - 2);
				}

				count += blockSize;
			}

			return blockSize;
		}
	}

}