using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.modes
{
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;

	/// <summary>
	/// Implements OpenPGP's rather strange version of Cipher-FeedBack (CFB) mode on top of a simple cipher. For further info see <a href="http://www.ietf.org/rfc/rfc2440.html">RFC 2440</a>.
	/// </summary>
	public class PGPCFBBlockCipher : BlockCipher
	{
		private byte[] IV;
		private byte[] FR;
		private byte[] FRE;
		private byte[] tmp;

		private BlockCipher cipher;

		private int count;
		private int blockSize;
		private bool forEncryption;

		private bool inlineIv; // if false we don't need to prepend an IV

		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="cipher"> the block cipher to be used as the basis of the
		/// feedback mode. </param>
		/// <param name="inlineIv"> if true this is for PGP CFB with a prepended iv. </param>
		public PGPCFBBlockCipher(BlockCipher cipher, bool inlineIv)
		{
			this.cipher = cipher;
			this.inlineIv = inlineIv;

			this.blockSize = cipher.getBlockSize();
			this.IV = new byte[blockSize];
			this.FR = new byte[blockSize];
			this.FRE = new byte[blockSize];
			this.tmp = new byte[blockSize];
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
		/// <returns> the name of the underlying algorithm followed by "/PGPCFB"
		/// and the block size in bits. </returns>
		public virtual string getAlgorithmName()
		{
			if (inlineIv)
			{
				return cipher.getAlgorithmName() + "/PGPCFBwithIV";
			}
			else
			{
				return cipher.getAlgorithmName() + "/PGPCFB";
			}
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
			if (inlineIv)
			{
				return (forEncryption) ? encryptBlockWithIV(@in, inOff, @out, outOff) : decryptBlockWithIV(@in, inOff, @out, outOff);
			}
			else
			{
				return (forEncryption) ? encryptBlock(@in, inOff, @out, outOff) : decryptBlock(@in, inOff, @out, outOff);
			}
		}

		/// <summary>
		/// reset the chaining vector back to the IV and reset the underlying
		/// cipher.
		/// </summary>
		public virtual void reset()
		{
			count = 0;

			for (int i = 0; i != FR.Length; i++)
			{
				if (inlineIv)
				{
					FR[i] = 0;
				}
				else
				{
					FR[i] = IV[i]; // if simple mode, key is IV (even if this is zero)
				}
			}

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

					cipher.init(true, ivParam.getParameters());
			}
			else
			{
					reset();

					cipher.init(true, @params);
			}
		}

		/// <summary>
		/// Encrypt one byte of data according to CFB mode. </summary>
		/// <param name="data"> the byte to encrypt </param>
		/// <param name="blockOff"> where am i in the current block, determines when to resync the block
		/// @returns the encrypted byte </param>
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
		private int encryptBlockWithIV(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if ((inOff + blockSize) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if (count == 0)
			{
				if ((outOff + 2 * blockSize + 2) > @out.Length)
				{
					throw new OutputLengthException("output buffer too short");
				}

				cipher.processBlock(FR, 0, FRE, 0);

				for (int n = 0; n < blockSize; n++)
				{
					@out[outOff + n] = encryptByte(IV[n], n);
				}

				JavaSystem.arraycopy(@out, outOff, FR, 0, blockSize);

				cipher.processBlock(FR, 0, FRE, 0);

				@out[outOff + blockSize] = encryptByte(IV[blockSize - 2], 0);
				@out[outOff + blockSize + 1] = encryptByte(IV[blockSize - 1], 1);

				JavaSystem.arraycopy(@out, outOff + 2, FR, 0, blockSize);

				cipher.processBlock(FR, 0, FRE, 0);

				for (int n = 0; n < blockSize; n++)
				{
					@out[outOff + blockSize + 2 + n] = encryptByte(@in[inOff + n], n);
				}

				JavaSystem.arraycopy(@out, outOff + blockSize + 2, FR, 0, blockSize);

				count += 2 * blockSize + 2;

				return 2 * blockSize + 2;
			}
			else if (count >= blockSize + 2)
			{
				if ((outOff + blockSize) > @out.Length)
				{
					throw new OutputLengthException("output buffer too short");
				}

				cipher.processBlock(FR, 0, FRE, 0);

				for (int n = 0; n < blockSize; n++)
				{
					@out[outOff + n] = encryptByte(@in[inOff + n], n);
				}

				JavaSystem.arraycopy(@out, outOff, FR, 0, blockSize);
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
		private int decryptBlockWithIV(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if ((inOff + blockSize) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}
			if ((outOff + blockSize) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			if (count == 0)
			{
				for (int n = 0; n < blockSize; n++)
				{
					FR[n] = @in[inOff + n];
				}

				cipher.processBlock(FR, 0, FRE, 0);

				count += blockSize;

				return 0;
			}
			else if (count == blockSize)
			{
				// copy in buffer so that this mode works if in and out are the same 
				JavaSystem.arraycopy(@in, inOff, tmp, 0, blockSize);

				JavaSystem.arraycopy(FR, 2, FR, 0, blockSize - 2);

				FR[blockSize - 2] = tmp[0];
				FR[blockSize - 1] = tmp[1];

				cipher.processBlock(FR, 0, FRE, 0);

				for (int n = 0; n < blockSize - 2; n++)
				{
					@out[outOff + n] = encryptByte(tmp[n + 2], n);
				}

				JavaSystem.arraycopy(tmp, 2, FR, 0, blockSize - 2);

				count += 2;

				return blockSize - 2;
			}
			else if (count >= blockSize + 2)
			{
				// copy in buffer so that this mode works if in and out are the same 
				JavaSystem.arraycopy(@in, inOff, tmp, 0, blockSize);

				@out[outOff + 0] = encryptByte(tmp[0], blockSize - 2);
				@out[outOff + 1] = encryptByte(tmp[1], blockSize - 1);

				JavaSystem.arraycopy(tmp, 0, FR, blockSize - 2, 2);

				cipher.processBlock(FR, 0, FRE, 0);

				for (int n = 0; n < blockSize - 2; n++)
				{
					@out[outOff + n + 2] = encryptByte(tmp[n + 2], n);
				}

				JavaSystem.arraycopy(tmp, 2, FR, 0, blockSize - 2);

			}

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

			cipher.processBlock(FR, 0, FRE, 0);
			for (int n = 0; n < blockSize; n++)
			{
				@out[outOff + n] = encryptByte(@in[inOff + n], n);
			}

			for (int n = 0; n < blockSize; n++)
			{
				FR[n] = @out[outOff + n];
			}

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

			cipher.processBlock(FR, 0, FRE, 0);
			for (int n = 0; n < blockSize; n++)
			{
				@out[outOff + n] = encryptByte(@in[inOff + n], n);
			}

			for (int n = 0; n < blockSize; n++)
			{
				FR[n] = @in[inOff + n];
			}

			return blockSize;

		}
	}

}