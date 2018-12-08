namespace org.bouncycastle.jcajce.io
{


	using InvalidCipherTextIOException = org.bouncycastle.crypto.io.InvalidCipherTextIOException;

	/// <summary>
	/// A CipherInputStream is composed of an InputStream and a cipher so that read() methods return data
	/// that are read in from the underlying InputStream but have been additionally processed by the
	/// Cipher. The cipher must be fully initialized before being used by a CipherInputStream.
	/// <para>
	/// For example, if the Cipher is initialized for decryption, the CipherInputStream will attempt to
	/// read in data and decrypt them, before returning the decrypted data.
	/// </para>
	/// </para><para>
	/// This is a reimplementation of <seealso cref="javax.crypto.CipherInputStream"/> that is safe for use with
	/// AEAD block ciphers, and does not silently catch <seealso cref="BadPaddingException"/> and
	/// <seealso cref="IllegalBlockSizeException"/> errors. Any errors that occur during {@link Cipher#doFinal()
	/// finalisation} are rethrown wrapped in an <seealso cref="InvalidCipherTextIOException"/>.
	/// </p>
	/// </summary>
	public class CipherInputStream : FilterInputStream
	{
		private readonly Cipher cipher;
		private readonly byte[] inputBuffer = new byte[512];
		private bool finalized = false;
		private byte[] buf;
		private int maxBuf;
		private int bufOff;

		/// <summary>
		/// Constructs a CipherInputStream from an InputStream and an initialised Cipher.
		/// </summary>
		public CipherInputStream(InputStream input, Cipher cipher) : base(input)
		{
			this.cipher = cipher;
		}

		/// <summary>
		/// Read data from underlying stream and process with cipher until end of stream or some data is
		/// available after cipher processing.
		/// </summary>
		/// <returns> -1 to indicate end of stream, or the number of bytes (> 0) available. </returns>
		private int nextChunk()
		{
			if (finalized)
			{
				return -1;
			}

			bufOff = 0;
			maxBuf = 0;

			// Keep reading until EOF or cipher processing produces data
			while (maxBuf == 0)
			{
				int read = @in.read(inputBuffer);
				if (read == -1)
				{
					buf = finaliseCipher();
					if ((buf == null) || (buf.Length == 0))
					{
						return -1;
					}
					maxBuf = buf.Length;
					return maxBuf;
				}

				buf = cipher.update(inputBuffer, 0, read);
				if (buf != null)
				{
					maxBuf = buf.Length;
				}
			}
			return maxBuf;
		}

		private byte[] finaliseCipher()
		{
			try
			{
				finalized = true;
				return cipher.doFinal();
			}
			catch (GeneralSecurityException e)
			{
				throw new InvalidCipherTextIOException("Error finalising cipher", e);
			}
		}

		/// <summary>
		/// Reads data from the underlying stream and processes it with the cipher until the cipher
		/// outputs data, and returns the next available byte.
		/// <para>
		/// If the underlying stream is exhausted by this call, the cipher will be finalised.
		/// </para> </summary>
		/// <exception cref="IOException"> if there was an error closing the input stream. </exception>
		/// <exception cref="InvalidCipherTextIOException"> if the data read from the stream was invalid ciphertext
		/// (e.g. the cipher is an AEAD cipher and the ciphertext tag check fails). </exception>
		public virtual int read()
		{
			if (bufOff >= maxBuf)
			{
				if (nextChunk() < 0)
				{
					return -1;
				}
			}

			return buf[bufOff++] & 0xff;
		}

		/// <summary>
		/// Reads data from the underlying stream and processes it with the cipher until the cipher
		/// outputs data, and then returns up to <code>len</code> bytes in the provided array.
		/// <para>
		/// If the underlying stream is exhausted by this call, the cipher will be finalised.
		/// </para> </summary>
		/// <param name="b">   the buffer into which the data is read. </param>
		/// <param name="off"> the start offset in the destination array <code>b</code> </param>
		/// <param name="len"> the maximum number of bytes read. </param>
		/// <returns> the total number of bytes read into the buffer, or <code>-1</code> if there is no
		///         more data because the end of the stream has been reached. </returns>
		/// <exception cref="IOException"> if there was an error closing the input stream. </exception>
		/// <exception cref="InvalidCipherTextIOException"> if the data read from the stream was invalid ciphertext
		/// (e.g. the cipher is an AEAD cipher and the ciphertext tag check fails). </exception>
		public virtual int read(byte[] b, int off, int len)
		{
			if (bufOff >= maxBuf)
			{
				if (nextChunk() < 0)
				{
					return -1;
				}
			}

			int toSupply = Math.Min(len, available());
			JavaSystem.arraycopy(buf, bufOff, b, off, toSupply);
			bufOff += toSupply;
			return toSupply;
		}

		public virtual long skip(long n)
		{
			if (n <= 0)
			{
				return 0;
			}

			int skip = (int)Math.Min(n, available());
			bufOff += skip;
			return skip;
		}

		public virtual int available()
		{
			return maxBuf - bufOff;
		}

		/// <summary>
		/// Closes the underlying input stream, and then finalises the processing of the data by the
		/// cipher.
		/// </summary>
		/// <exception cref="IOException"> if there was an error closing the input stream. </exception>
		/// <exception cref="InvalidCipherTextIOException"> if the data read from the stream was invalid ciphertext
		/// (e.g. the cipher is an AEAD cipher and the ciphertext tag check fails). </exception>
		public virtual void close()
		{
			try
			{
				@in.close();
			}
			finally
			{
				if (!finalized)
				{
					// Reset the cipher, discarding any data buffered in it
					// Errors in cipher finalisation trump I/O error closing input
					finaliseCipher();
				}
			}
			maxBuf = bufOff = 0;
		}

		public virtual void mark(int readlimit)
		{
		}

		public virtual void reset()
		{
		}

		public virtual bool markSupported()
		{
			return false;
		}

	}

}