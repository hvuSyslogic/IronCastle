using org.bouncycastle.crypto.paddings;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.macs
{
		
	/// <summary>
	/// implements a Cipher-FeedBack (CFB) mode on top of a simple cipher.
	/// </summary>
	public class MacCFBBlockCipher
	{
		private byte[] IV;
		private byte[] cfbV;
		private byte[] cfbOutV;

		private int blockSize;
		private BlockCipher cipher = null;

		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="cipher"> the block cipher to be used as the basis of the
		/// feedback mode. </param>
		/// <param name="blockSize"> the block size in bits (note: a multiple of 8) </param>
		public MacCFBBlockCipher(BlockCipher cipher, int bitBlockSize)
		{
			this.cipher = cipher;
			this.blockSize = bitBlockSize / 8;

			this.IV = new byte[cipher.getBlockSize()];
			this.cfbV = new byte[cipher.getBlockSize()];
			this.cfbOutV = new byte[cipher.getBlockSize()];
		}

		/// <summary>
		/// Initialise the cipher and, possibly, the initialisation vector (IV).
		/// If an IV isn't passed as part of the parameter, the IV will be all zeros.
		/// An IV which is too short is handled in FIPS compliant fashion.
		/// </summary>
		/// <param name="param"> the key and other data required by the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		public virtual void init(CipherParameters @params)
		{
			if (@params is ParametersWithIV)
			{
					ParametersWithIV ivParam = (ParametersWithIV)@params;
					byte[] iv = ivParam.getIV();

					if (iv.Length < IV.Length)
					{
						JavaSystem.arraycopy(iv, 0, IV, IV.Length - iv.Length, iv.Length);
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
		/// return the algorithm name and mode.
		/// </summary>
		/// <returns> the name of the underlying algorithm followed by "/CFB"
		/// and the block size in bits. </returns>
		public virtual string getAlgorithmName()
		{
			return cipher.getAlgorithmName() + "/CFB" + (blockSize * 8);
		}

		/// <summary>
		/// return the block size we are operating at.
		/// </summary>
		/// <returns> the block size we are operating at (in bytes). </returns>
		public virtual int getBlockSize()
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
		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if ((inOff + blockSize) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOff + blockSize) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			cipher.processBlock(cfbV, 0, cfbOutV, 0);

			//
			// XOR the cfbV with the plaintext producing the cipher text
			//
			for (int i = 0; i < blockSize; i++)
			{
				@out[outOff + i] = (byte)(cfbOutV[i] ^ @in[inOff + i]);
			}

			//
			// change over the input block.
			//
			JavaSystem.arraycopy(cfbV, blockSize, cfbV, 0, cfbV.Length - blockSize);
			JavaSystem.arraycopy(@out, outOff, cfbV, cfbV.Length - blockSize, blockSize);

			return blockSize;
		}

		/// <summary>
		/// reset the chaining vector back to the IV and reset the underlying
		/// cipher.
		/// </summary>
		public virtual void reset()
		{
			JavaSystem.arraycopy(IV, 0, cfbV, 0, IV.Length);

			cipher.reset();
		}

		public virtual void getMacBlock(byte[] mac)
		{
			cipher.processBlock(cfbV, 0, mac, 0);
		}
	}

	public class CFBBlockCipherMac : Mac
	{
		private byte[] mac;

		private byte[] buf;
		private int bufOff;
		private MacCFBBlockCipher cipher;
		private BlockCipherPadding padding = null;


		private int macSize;

		/// <summary>
		/// create a standard MAC based on a CFB block cipher. This will produce an
		/// authentication code half the length of the block size of the cipher, with
		/// the CFB mode set to 8 bits.
		/// </summary>
		/// <param name="cipher"> the cipher to be used as the basis of the MAC generation. </param>
		public CFBBlockCipherMac(BlockCipher cipher) : this(cipher, 8, (cipher.getBlockSize() * 8) / 2, null)
		{
		}

		/// <summary>
		/// create a standard MAC based on a CFB block cipher. This will produce an
		/// authentication code half the length of the block size of the cipher, with
		/// the CFB mode set to 8 bits.
		/// </summary>
		/// <param name="cipher"> the cipher to be used as the basis of the MAC generation. </param>
		/// <param name="padding"> the padding to be used. </param>
		public CFBBlockCipherMac(BlockCipher cipher, BlockCipherPadding padding) : this(cipher, 8, (cipher.getBlockSize() * 8) / 2, padding)
		{
		}

		/// <summary>
		/// create a standard MAC based on a block cipher with the size of the
		/// MAC been given in bits. This class uses CFB mode as the basis for the
		/// MAC generation.
		/// <para>
		/// Note: the size of the MAC must be at least 24 bits (FIPS Publication 81),
		/// or 16 bits if being used as a data authenticator (FIPS Publication 113),
		/// and in general should be less than the size of the block cipher as it reduces
		/// the chance of an exhaustive attack (see Handbook of Applied Cryptography).
		/// 
		/// </para>
		/// </summary>
		/// <param name="cipher"> the cipher to be used as the basis of the MAC generation. </param>
		/// <param name="cfbBitSize"> the size of an output block produced by the CFB mode. </param>
		/// <param name="macSizeInBits"> the size of the MAC in bits, must be a multiple of 8. </param>
		public CFBBlockCipherMac(BlockCipher cipher, int cfbBitSize, int macSizeInBits) : this(cipher, cfbBitSize, macSizeInBits, null)
		{
		}

		/// <summary>
		/// create a standard MAC based on a block cipher with the size of the
		/// MAC been given in bits. This class uses CFB mode as the basis for the
		/// MAC generation.
		/// <para>
		/// Note: the size of the MAC must be at least 24 bits (FIPS Publication 81),
		/// or 16 bits if being used as a data authenticator (FIPS Publication 113),
		/// and in general should be less than the size of the block cipher as it reduces
		/// the chance of an exhaustive attack (see Handbook of Applied Cryptography).
		/// 
		/// </para>
		/// </summary>
		/// <param name="cipher"> the cipher to be used as the basis of the MAC generation. </param>
		/// <param name="cfbBitSize"> the size of an output block produced by the CFB mode. </param>
		/// <param name="macSizeInBits"> the size of the MAC in bits, must be a multiple of 8. </param>
		/// <param name="padding"> a padding to be used. </param>
		public CFBBlockCipherMac(BlockCipher cipher, int cfbBitSize, int macSizeInBits, BlockCipherPadding padding)
		{
			if ((macSizeInBits % 8) != 0)
			{
				throw new IllegalArgumentException("MAC size must be multiple of 8");
			}

			mac = new byte[cipher.getBlockSize()];

			this.cipher = new MacCFBBlockCipher(cipher, cfbBitSize);
			this.padding = padding;
			this.macSize = macSizeInBits / 8;

			buf = new byte[this.cipher.getBlockSize()];
			bufOff = 0;
		}

		public virtual string getAlgorithmName()
		{
			return cipher.getAlgorithmName();
		}

		public virtual void init(CipherParameters @params)
		{
			reset();

			cipher.init(@params);
		}

		public virtual int getMacSize()
		{
			return macSize;
		}

		public virtual void update(byte @in)
		{
			if (bufOff == buf.Length)
			{
				cipher.processBlock(buf, 0, mac, 0);
				bufOff = 0;
			}

			buf[bufOff++] = @in;
		}

		public virtual void update(byte[] @in, int inOff, int len)
		{
			if (len < 0)
			{
				throw new IllegalArgumentException("Can't have a negative input length!");
			}

			int blockSize = cipher.getBlockSize();
			int resultLen = 0;
			int gapLen = blockSize - bufOff;

			if (len > gapLen)
			{
				JavaSystem.arraycopy(@in, inOff, buf, bufOff, gapLen);

				resultLen += cipher.processBlock(buf, 0, mac, 0);

				bufOff = 0;
				len -= gapLen;
				inOff += gapLen;

				while (len > blockSize)
				{
					resultLen += cipher.processBlock(@in, inOff, mac, 0);

					len -= blockSize;
					inOff += blockSize;
				}
			}

			JavaSystem.arraycopy(@in, inOff, buf, bufOff, len);

			bufOff += len;
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			int blockSize = cipher.getBlockSize();

			//
			// pad with zeroes
			//
			if (this.padding == null)
			{
				while (bufOff < blockSize)
				{
					buf[bufOff] = 0;
					bufOff++;
				}
			}
			else
			{
				padding.addPadding(buf, bufOff);
			}

			cipher.processBlock(buf, 0, mac, 0);

			cipher.getMacBlock(mac);

			JavaSystem.arraycopy(mac, 0, @out, outOff, macSize);

			reset();

			return macSize;
		}

		/// <summary>
		/// Reset the mac generator.
		/// </summary>
		public virtual void reset()
		{
			/*
			 * clean the buffer.
			 */
			for (int i = 0; i < buf.Length; i++)
			{
				buf[i] = 0;
			}

			bufOff = 0;

			/*
			 * reset the underlying cipher.
			 */
			cipher.reset();
		}
	}

}