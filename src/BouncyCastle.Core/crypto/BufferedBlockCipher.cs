using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto
{

	/// <summary>
	/// A wrapper class that allows block ciphers to be used to process data in
	/// a piecemeal fashion. The BufferedBlockCipher outputs a block only when the
	/// buffer is full and more data is being added, or on a doFinal.
	/// <para>
	/// Note: in the case where the underlying cipher is either a CFB cipher or an
	/// OFB one the last block may not be a multiple of the block size.
	/// </para>
	/// </summary>
	public class BufferedBlockCipher
	{
		protected internal byte[] buf;
		protected internal int bufOff;

		protected internal bool forEncryption;
		protected internal BlockCipher cipher;

		protected internal bool partialBlockOkay;
		protected internal bool pgpCFB;

		/// <summary>
		/// constructor for subclasses
		/// </summary>
		public BufferedBlockCipher()
		{
		}

		/// <summary>
		/// Create a buffered block cipher without padding.
		/// </summary>
		/// <param name="cipher"> the underlying block cipher this buffering object wraps. </param>
		public BufferedBlockCipher(BlockCipher cipher)
		{
			this.cipher = cipher;

			buf = new byte[cipher.getBlockSize()];
			bufOff = 0;

			//
			// check if we can handle partial blocks on doFinal.
			//
			string name = cipher.getAlgorithmName();
			int idx = name.IndexOf('/') + 1;

			pgpCFB = (idx > 0 && name.StartsWith("PGP", idx));

			if (pgpCFB || cipher is StreamCipher)
			{
				partialBlockOkay = true;
			}
			else
			{
				partialBlockOkay = (idx > 0 && (name.StartsWith("OpenPGP", idx)));
			}
		}

		/// <summary>
		/// return the cipher this object wraps.
		/// </summary>
		/// <returns> the cipher this object wraps. </returns>
		public virtual BlockCipher getUnderlyingCipher()
		{
			return cipher;
		}

		/// <summary>
		/// initialise the cipher.
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

			cipher.init(forEncryption, @params);
		}

		/// <summary>
		/// return the blocksize for the underlying cipher.
		/// </summary>
		/// <returns> the blocksize for the underlying cipher. </returns>
		public virtual int getBlockSize()
		{
			return cipher.getBlockSize();
		}

		/// <summary>
		/// return the size of the output buffer required for an update 
		/// an input of len bytes.
		/// </summary>
		/// <param name="len"> the length of the input. </param>
		/// <returns> the space required to accommodate a call to update
		/// with len bytes of input. </returns>
		public virtual int getUpdateOutputSize(int len)
		{
			int total = len + bufOff;
			int leftOver;

			if (pgpCFB)
			{
				if (forEncryption)
				{
					leftOver = total % buf.Length - (cipher.getBlockSize() + 2);
				}
				else
				{
					leftOver = total % buf.Length;
				}
			}
			else
			{
				leftOver = total % buf.Length;
			}

			return total - leftOver;
		}

		/// <summary>
		/// return the size of the output buffer required for an update plus a
		/// doFinal with an input of 'length' bytes.
		/// </summary>
		/// <param name="length"> the length of the input. </param>
		/// <returns> the space required to accommodate a call to update and doFinal
		/// with 'length' bytes of input. </returns>
		public virtual int getOutputSize(int length)
		{
			// Note: Can assume partialBlockOkay is true for purposes of this calculation
			return length + bufOff;
		}

		/// <summary>
		/// process a single byte, producing an output block if necessary.
		/// </summary>
		/// <param name="in"> the input byte. </param>
		/// <param name="out"> the space for any output that might be produced. </param>
		/// <param name="outOff"> the offset from which the output will be copied. </param>
		/// <returns> the number of output bytes copied to out. </returns>
		/// <exception cref="DataLengthException"> if there isn't enough space in out. </exception>
		/// <exception cref="IllegalStateException"> if the cipher isn't initialised. </exception>
		public virtual int processByte(byte @in, byte[] @out, int outOff)
		{
			int resultLen = 0;

			buf[bufOff++] = @in;

			if (bufOff == buf.Length)
			{
				resultLen = cipher.processBlock(buf, 0, @out, outOff);
				bufOff = 0;
			}

			return resultLen;
		}

		/// <summary>
		/// process an array of bytes, producing output if necessary.
		/// </summary>
		/// <param name="in"> the input byte array. </param>
		/// <param name="inOff"> the offset at which the input data starts. </param>
		/// <param name="len"> the number of bytes to be copied out of the input array. </param>
		/// <param name="out"> the space for any output that might be produced. </param>
		/// <param name="outOff"> the offset from which the output will be copied. </param>
		/// <returns> the number of output bytes copied to out. </returns>
		/// <exception cref="DataLengthException"> if there isn't enough space in out. </exception>
		/// <exception cref="IllegalStateException"> if the cipher isn't initialised. </exception>
		public virtual int processBytes(byte[] @in, int inOff, int len, byte[] @out, int outOff)
		{
			if (len < 0)
			{
				throw new IllegalArgumentException("Can't have a negative input length!");
			}

			int blockSize = getBlockSize();
			int length = getUpdateOutputSize(len);

			if (length > 0)
			{
				if ((outOff + length) > @out.Length)
				{
					throw new OutputLengthException("output buffer too short");
				}
			}

			int resultLen = 0;
			int gapLen = buf.Length - bufOff;

			if (len > gapLen)
			{
				JavaSystem.arraycopy(@in, inOff, buf, bufOff, gapLen);

				resultLen += cipher.processBlock(buf, 0, @out, outOff);

				bufOff = 0;
				len -= gapLen;
				inOff += gapLen;

				while (len > buf.Length)
				{
					resultLen += cipher.processBlock(@in, inOff, @out, outOff + resultLen);

					len -= blockSize;
					inOff += blockSize;
				}
			}

			JavaSystem.arraycopy(@in, inOff, buf, bufOff, len);

			bufOff += len;

			if (bufOff == buf.Length)
			{
				resultLen += cipher.processBlock(buf, 0, @out, outOff + resultLen);
				bufOff = 0;
			}

			return resultLen;
		}

		/// <summary>
		/// Process the last block in the buffer.
		/// </summary>
		/// <param name="out"> the array the block currently being held is copied into. </param>
		/// <param name="outOff"> the offset at which the copying starts. </param>
		/// <returns> the number of output bytes copied to out. </returns>
		/// <exception cref="DataLengthException"> if there is insufficient space in out for
		/// the output, or the input is not block size aligned and should be. </exception>
		/// <exception cref="IllegalStateException"> if the underlying cipher is not
		/// initialised. </exception>
		/// <exception cref="InvalidCipherTextException"> if padding is expected and not found. </exception>
		/// <exception cref="DataLengthException"> if the input is not block size
		/// aligned. </exception>
		public virtual int doFinal(byte[] @out, int outOff)
		{
			try
			{
				int resultLen = 0;

				if (outOff + bufOff > @out.Length)
				{
					throw new OutputLengthException("output buffer too short for doFinal()");
				}

				if (bufOff != 0)
				{
					if (!partialBlockOkay)
					{
						throw new DataLengthException("data not block size aligned");
					}

					cipher.processBlock(buf, 0, buf, 0);
					resultLen = bufOff;
					bufOff = 0;
					JavaSystem.arraycopy(buf, 0, @out, outOff, resultLen);
				}

				return resultLen;
			}
			finally
			{
				reset();
			}
		}

		/// <summary>
		/// Reset the buffer and cipher. After resetting the object is in the same
		/// state as it was after the last init (if there was one).
		/// </summary>
		public virtual void reset()
		{
			//
			// clean the buffer.
			//
			for (int i = 0; i < buf.Length; i++)
			{
				buf[i] = 0;
			}

			bufOff = 0;

			//
			// reset the underlying cipher.
			//
			cipher.reset();
		}
	}

}