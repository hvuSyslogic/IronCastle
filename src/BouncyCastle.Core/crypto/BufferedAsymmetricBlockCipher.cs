using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto
{
	/// <summary>
	/// a buffer wrapper for an asymmetric block cipher, allowing input
	/// to be accumulated in a piecemeal fashion until final processing.
	/// </summary>
	public class BufferedAsymmetricBlockCipher
	{
		protected internal byte[] buf;
		protected internal int bufOff;

		private readonly AsymmetricBlockCipher cipher;

		/// <summary>
		/// base constructor.
		/// </summary>
		/// <param name="cipher"> the cipher this buffering object wraps. </param>
		public BufferedAsymmetricBlockCipher(AsymmetricBlockCipher cipher)
		{
			this.cipher = cipher;
		}

		/// <summary>
		/// return the underlying cipher for the buffer.
		/// </summary>
		/// <returns> the underlying cipher for the buffer. </returns>
		public virtual AsymmetricBlockCipher getUnderlyingCipher()
		{
			return cipher;
		}

		/// <summary>
		/// return the amount of data sitting in the buffer.
		/// </summary>
		/// <returns> the amount of data sitting in the buffer. </returns>
		public virtual int getBufferPosition()
		{
			return bufOff;
		}

		/// <summary>
		/// initialise the buffer and the underlying cipher.
		/// </summary>
		/// <param name="forEncryption"> if true the cipher is initialised for
		///  encryption, if false for decryption. </param>
		/// <param name="params"> the key and other data required by the cipher. </param>
		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			reset();

			cipher.init(forEncryption, @params);

			//
			// we allow for an extra byte where people are using their own padding
			// mechanisms on a raw cipher.
			//
			buf = new byte[cipher.getInputBlockSize() + (forEncryption ? 1 : 0)];
			bufOff = 0;
		}

		/// <summary>
		/// returns the largest size an input block can be.
		/// </summary>
		/// <returns> maximum size for an input block. </returns>
		public virtual int getInputBlockSize()
		{
			return cipher.getInputBlockSize();
		}

		/// <summary>
		/// returns the maximum size of the block produced by this cipher.
		/// </summary>
		/// <returns> maximum size of the output block produced by the cipher. </returns>
		public virtual int getOutputBlockSize()
		{
			return cipher.getOutputBlockSize();
		}

		/// <summary>
		/// add another byte for processing.
		/// </summary>
		/// <param name="in"> the input byte. </param>
		public virtual void processByte(byte @in)
		{
			if (bufOff >= buf.Length)
			{
				throw new DataLengthException("attempt to process message too long for cipher");
			}

			buf[bufOff++] = @in;
		}

		/// <summary>
		/// add len bytes to the buffer for processing.
		/// </summary>
		/// <param name="in"> the input data </param>
		/// <param name="inOff"> offset into the in array where the data starts </param>
		/// <param name="len"> the length of the block to be processed. </param>
		public virtual void processBytes(byte[] @in, int inOff, int len)
		{
			if (len == 0)
			{
				return;
			}

			if (len < 0)
			{
				throw new IllegalArgumentException("Can't have a negative input length!");
			}

			if (bufOff + len > buf.Length)
			{
				throw new DataLengthException("attempt to process message too long for cipher");
			}

			JavaSystem.arraycopy(@in, inOff, buf, bufOff, len);
			bufOff += len;
		}

		/// <summary>
		/// process the contents of the buffer using the underlying
		/// cipher.
		/// </summary>
		/// <returns> the result of the encryption/decryption process on the
		/// buffer. </returns>
		/// <exception cref="InvalidCipherTextException"> if we are given a garbage block. </exception>
		public virtual byte[] doFinal()
		{
			byte[] @out = cipher.processBlock(buf, 0, bufOff);

			reset();

			return @out;
		}

		/// <summary>
		/// Reset the buffer and the underlying cipher.
		/// </summary>
		public virtual void reset()
		{
			/*
			 * clean the buffer.
			 */
			if (buf != null)
			{
				for (int i = 0; i < buf.Length; i++)
				{
					buf[i] = 0;
				}
			}

			bufOff = 0;
		}
	}

}