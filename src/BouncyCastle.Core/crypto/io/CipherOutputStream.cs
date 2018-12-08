using System;
using System.IO;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.io
{

	using AEADBlockCipher = org.bouncycastle.crypto.modes.AEADBlockCipher;

	/// <summary>
	/// A CipherOutputStream is composed of an OutputStream and a cipher so that write() methods process
	/// the written data with the cipher, and the output of the cipher is in turn written to the
	/// underlying OutputStream. The cipher must be fully initialized before being used by a
	/// CipherInputStream.
	/// <para>
	/// For example, if the cipher is initialized for encryption, the CipherOutputStream will encrypt the
	/// data before writing the encrypted data to the underlying stream.
	/// </para>
	/// </summary>
	public class CipherOutputStream : FilterOutputStream
	{
		private BufferedBlockCipher bufferedBlockCipher;
		private StreamCipher streamCipher;
		private AEADBlockCipher aeadBlockCipher;

		private readonly byte[] oneByte = new byte[1];
		private byte[] buf;

		/// <summary>
		/// Constructs a CipherOutputStream from an OutputStream and a
		/// BufferedBlockCipher.
		/// </summary>
		public CipherOutputStream(OutputStream os, BufferedBlockCipher cipher) : base(os)
		{
			this.bufferedBlockCipher = cipher;
		}

		/// <summary>
		/// Constructs a CipherOutputStream from an OutputStream and a
		/// BufferedBlockCipher.
		/// </summary>
		public CipherOutputStream(OutputStream os, StreamCipher cipher) : base(os)
		{
			this.streamCipher = cipher;
		}

		/// <summary>
		/// Constructs a CipherOutputStream from an OutputStream and a AEADBlockCipher.
		/// </summary>
		public CipherOutputStream(OutputStream os, AEADBlockCipher cipher) : base(os)
		{
			this.aeadBlockCipher = cipher;
		}

		/// <summary>
		/// Writes the specified byte to this output stream.
		/// </summary>
		/// <param name="b"> the <code>byte</code>. </param>
		/// <exception cref="IOException"> if an I/O error occurs. </exception>
		public virtual void write(int b)
		{
			oneByte[0] = (byte)b;

			if (streamCipher != null)
			{
				@out.write(streamCipher.returnByte((byte)b));
			}
			else
			{
				write(oneByte, 0, 1);
			}
		}

		/// <summary>
		/// Writes <code>b.length</code> bytes from the specified byte array
		/// to this output stream.
		/// <para>
		/// The <code>write</code> method of
		/// <code>CipherOutputStream</code> calls the <code>write</code>
		/// method of three arguments with the three arguments
		/// <code>b</code>, <code>0</code>, and <code>b.length</code>.
		/// 
		/// </para>
		/// </summary>
		/// <param name="b"> the data. </param>
		/// <exception cref="IOException"> if an I/O error occurs. </exception>
		/// <seealso cref= #write(byte[], int, int) </seealso>
		public virtual void write(byte[] b)
		{
			write(b, 0, b.Length);
		}

		/// <summary>
		/// Writes <code>len</code> bytes from the specified byte array
		/// starting at offset <code>off</code> to this output stream.
		/// </summary>
		/// <param name="b">   the data. </param>
		/// <param name="off"> the start offset in the data. </param>
		/// <param name="len"> the number of bytes to write. </param>
		/// <exception cref="IOException"> if an I/O error occurs. </exception>
		public virtual void write(byte[] b, int off, int len)
		{
			ensureCapacity(len, false);

			if (bufferedBlockCipher != null)
			{
				int outLen = bufferedBlockCipher.processBytes(b, off, len, buf, 0);

				if (outLen != 0)
				{
					@out.write(buf, 0, outLen);
				}
			}
			else if (aeadBlockCipher != null)
			{
				int outLen = aeadBlockCipher.processBytes(b, off, len, buf, 0);

				if (outLen != 0)
				{
					@out.write(buf, 0, outLen);
				}
			}
			else
			{
				streamCipher.processBytes(b, off, len, buf, 0);

				@out.write(buf, 0, len);
			}
		}

		/// <summary>
		/// Ensure the ciphertext buffer has space sufficient to accept an upcoming output.
		/// </summary>
		/// <param name="updateSize"> the size of the pending update. </param>
		/// <param name="finalOutput"> <code>true</code> iff this the cipher is to be finalised. </param>
		private void ensureCapacity(int updateSize, bool finalOutput)
		{
			int bufLen = updateSize;
			if (finalOutput)
			{
				if (bufferedBlockCipher != null)
				{
					bufLen = bufferedBlockCipher.getOutputSize(updateSize);
				}
				else if (aeadBlockCipher != null)
				{
					bufLen = aeadBlockCipher.getOutputSize(updateSize);
				}
			}
			else
			{
				if (bufferedBlockCipher != null)
				{
					bufLen = bufferedBlockCipher.getUpdateOutputSize(updateSize);
				}
				else if (aeadBlockCipher != null)
				{
					bufLen = aeadBlockCipher.getUpdateOutputSize(updateSize);
				}
			}

			if ((buf == null) || (buf.Length < bufLen))
			{
				buf = new byte[bufLen];
			}
		}

		/// <summary>
		/// Flushes this output stream by forcing any buffered output bytes
		/// that have already been processed by the encapsulated cipher object
		/// to be written out.
		/// <para>
		/// Any bytes buffered by the encapsulated cipher
		/// and waiting to be processed by it will not be written out. For example,
		/// if the encapsulated cipher is a block cipher, and the total number of
		/// bytes written using one of the <code>write</code> methods is less than
		/// the cipher's block size, no bytes will be written out.
		/// 
		/// </para>
		/// </summary>
		/// <exception cref="IOException"> if an I/O error occurs. </exception>
		public virtual void flush()
		{
			@out.flush();
		}

		/// <summary>
		/// Closes this output stream and releases any system resources
		/// associated with this stream.
		/// <para>
		/// This method invokes the <code>doFinal</code> method of the encapsulated
		/// cipher object, which causes any bytes buffered by the encapsulated
		/// cipher to be processed. The result is written out by calling the
		/// <code>flush</code> method of this output stream.
		/// </para>
		/// <para>
		/// This method resets the encapsulated cipher object to its initial state
		/// and calls the <code>close</code> method of the underlying output
		/// stream.
		/// 
		/// </para>
		/// </summary>
		/// <exception cref="IOException"> if an I/O error occurs. </exception>
		/// <exception cref="InvalidCipherTextIOException"> if the data written to this stream was invalid ciphertext
		/// (e.g. the cipher is an AEAD cipher and the ciphertext tag check fails). </exception>
		public virtual void close()
		{
			ensureCapacity(0, true);
			IOException error = null;
			try
			{
				if (bufferedBlockCipher != null)
				{
					int outLen = bufferedBlockCipher.doFinal(buf, 0);

					if (outLen != 0)
					{
						@out.write(buf, 0, outLen);
					}
				}
				else if (aeadBlockCipher != null)
				{
					int outLen = aeadBlockCipher.doFinal(buf, 0);

					if (outLen != 0)
					{
						@out.write(buf, 0, outLen);
					}
				}
				else if (streamCipher != null)
				{
					streamCipher.reset();
				}
			}
//JAVA TO C# CONVERTER WARNING: 'final' catch parameters are not available in C#:
//ORIGINAL LINE: catch (final org.bouncycastle.crypto.InvalidCipherTextException e)
			catch (InvalidCipherTextException e)
			{
				error = new InvalidCipherTextIOException("Error finalising cipher data", e);
			}
			catch (Exception e)
			{
				error = new CipherIOException("Error closing stream: ", e);
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