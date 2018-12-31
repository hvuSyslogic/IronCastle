using org.bouncycastle.crypto.modes;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.macs
{
	
	public class BlockCipherMac : Mac
	{
		private byte[] mac;

		private byte[] buf;
		private int bufOff;
		private BlockCipher cipher;

		private int macSize;

		/// <summary>
		/// create a standard MAC based on a block cipher. This will produce an
		/// authentication code half the length of the block size of the cipher.
		/// </summary>
		/// <param name="cipher"> the cipher to be used as the basis of the MAC generation. </param>
		/// @deprecated use CBCBlockCipherMac 
		public BlockCipherMac(BlockCipher cipher) : this(cipher, (cipher.getBlockSize() * 8) / 2)
		{
		}

		/// <summary>
		/// create a standard MAC based on a block cipher with the size of the
		/// MAC been given in bits.
		/// <para>
		/// Note: the size of the MAC must be at least 16 bits (FIPS Publication 113),
		/// and in general should be less than the size of the block cipher as it reduces
		/// the chance of an exhaustive attack (see Handbook of Applied Cryptography).
		/// 
		/// </para>
		/// </summary>
		/// <param name="cipher"> the cipher to be used as the basis of the MAC generation. </param>
		/// <param name="macSizeInBits"> the size of the MAC in bits, must be a multiple of 8. </param>
		/// @deprecated use CBCBlockCipherMac 
		public BlockCipherMac(BlockCipher cipher, int macSizeInBits)
		{
			if ((macSizeInBits % 8) != 0)
			{
				throw new IllegalArgumentException("MAC size must be multiple of 8");
			}

			this.cipher = new CBCBlockCipher(cipher);
			this.macSize = macSizeInBits / 8;

			mac = new byte[cipher.getBlockSize()];

			buf = new byte[cipher.getBlockSize()];
			bufOff = 0;
		}

		public virtual string getAlgorithmName()
		{
			return cipher.getAlgorithmName();
		}

		public virtual void init(CipherParameters @params)
		{
			reset();

			cipher.init(true, @params);
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
			while (bufOff < blockSize)
			{
				buf[bufOff] = 0;
				bufOff++;
			}

			cipher.processBlock(buf, 0, mac, 0);

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