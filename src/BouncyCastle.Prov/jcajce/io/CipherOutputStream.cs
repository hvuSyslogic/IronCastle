using System;

namespace org.bouncycastle.jcajce.io
{


	using InvalidCipherTextIOException = org.bouncycastle.crypto.io.InvalidCipherTextIOException;

	/// <summary>
	/// A CipherOutputStream is composed of an OutputStream and a cipher so that write() methods process
	/// the written data with the cipher, and the output of the cipher is in turn written to the
	/// underlying OutputStream. The cipher must be fully initialized before being used by a
	/// CipherInputStream.
	/// <para>
	/// For example, if the cipher is initialized for encryption, the CipherOutputStream will encrypt the
	/// data before writing the encrypted data to the underlying stream.
	/// </para>
	/// </para><para>
	/// This is a reimplementation of <seealso cref="javax.crypto.CipherOutputStream"/> that is safe for use with
	/// AEAD block ciphers, and does not silently catch <seealso cref="BadPaddingException"/> and
	/// <seealso cref="IllegalBlockSizeException"/> errors. Any errors that occur during {@link Cipher#doFinal()
	/// finalisation} are rethrown wrapped in an <seealso cref="InvalidCipherTextIOException"/>.
	/// </p>
	/// </summary>
	public class CipherOutputStream : FilterOutputStream
	{
		private readonly Cipher cipher;
		private readonly byte[] oneByte = new byte[1];

		/// <summary>
		/// Constructs a CipherOutputStream from an OutputStream and a Cipher.
		/// </summary>
		public CipherOutputStream(OutputStream output, Cipher cipher) : base(output)
		{
			this.cipher = cipher;
		}

		/// <summary>
		/// Writes the specified byte to this output stream.
		/// </summary>
		/// <param name="b"> the <code>byte</code>. </param>
		/// <exception cref="java.io.IOException"> if an I/O error occurs. </exception>
		public virtual void write(int b)
		{
			oneByte[0] = (byte)b;
			write(oneByte, 0, 1);
		}

		/// <summary>
		/// Writes <code>len</code> bytes from the specified byte array starting at offset
		/// <code>off</code> to this output stream.
		/// </summary>
		/// <param name="b">   the data. </param>
		/// <param name="off"> the start offset in the data. </param>
		/// <param name="len"> the number of bytes to write. </param>
		/// <exception cref="java.io.IOException"> if an I/O error occurs. </exception>
		public virtual void write(byte[] b, int off, int len)
		{
			byte[] outData = cipher.update(b, off, len);
			if (outData != null)
			{
				@out.write(outData);
			}
		}

		/// <summary>
		/// Flushes this output stream by forcing any buffered output bytes that have already been
		/// processed by the encapsulated cipher object to be written out.
		/// <para>
		/// Any bytes buffered by the encapsulated cipher and waiting to be processed by it will not be
		/// written out. For example, if the encapsulated cipher is a block cipher, and the total number
		/// of bytes written using one of the <code>write</code> methods is less than the cipher's block
		/// size, no bytes will be written out.
		/// </para> </summary>
		/// <exception cref="java.io.IOException"> if an I/O error occurs. </exception>
		public virtual void flush()
		{
			@out.flush();
		}

		/// <summary>
		/// Closes this output stream and releases any system resources associated with this stream.
		/// <para>
		/// This method invokes the <code>doFinal</code> method of the encapsulated cipher object, which
		/// causes any bytes buffered by the encapsulated cipher to be processed. The result is written
		/// out by calling the <code>flush</code> method of this output stream.
		/// </para>
		/// </para><para>
		/// This method resets the encapsulated cipher object to its initial state and calls the
		/// <code>close</code> method of the underlying output stream.
		/// </p> </summary>
		/// <exception cref="java.io.IOException"> if an I/O error occurs. </exception>
		/// <exception cref="InvalidCipherTextIOException"> if the data written to this stream was invalid
		/// ciphertext (e.g. the cipher is an AEAD cipher and the ciphertext tag check
		/// fails). </exception>
		public virtual void close()
		{
			IOException error = null;
			try
			{
				byte[] outData = cipher.doFinal();
				if (outData != null)
				{
					@out.write(outData);
				}
			}
			catch (GeneralSecurityException e)
			{
				error = new InvalidCipherTextIOException("Error during cipher finalisation", e);
			}
			catch (Exception e)
			{
				error = new IOException("Error closing stream: " + e);
			}
			try
			{
				flush();
				@out.close();
			}
			catch (IOException e)
			{
				// Invalid ciphertext takes precedence over close error
				if (error == null)
				{
					error = e;
				}
			}
			if (error != null)
			{
				throw error;
			}
		}

	}

}