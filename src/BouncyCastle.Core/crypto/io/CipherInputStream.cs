using System;
using System.IO;
using org.bouncycastle.notexisting;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.io
{

	using AEADBlockCipher = org.bouncycastle.crypto.modes.AEADBlockCipher;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// A CipherInputStream is composed of an InputStream and a cipher so that read() methods return data
	/// that are read in from the underlying InputStream but have been additionally processed by the
	/// Cipher. The cipher must be fully initialized before being used by a CipherInputStream.
	/// <para>
	/// For example, if the Cipher is initialized for decryption, the
	/// CipherInputStream will attempt to read in data and decrypt them,
	/// before returning the decrypted data.
	/// </para>
	/// </summary>
	public class CipherInputStream : FilterInputStream
	{
		private const int INPUT_BUF_SIZE = 2048;

		private SkippingCipher skippingCipher;
		private byte[] inBuf;

		private BufferedBlockCipher bufferedBlockCipher;
		private StreamCipher streamCipher;
		private AEADBlockCipher aeadBlockCipher;

		private byte[] buf;
		private byte[] markBuf;


		private int bufOff;
		private int maxBuf;
		private bool finalized;
		private long markPosition;
		private int markBufOff;

		/// <summary>
		/// Constructs a CipherInputStream from an InputStream and a
		/// BufferedBlockCipher.
		/// </summary>
		public CipherInputStream(InputStream @is, BufferedBlockCipher cipher) : this(@is, cipher, INPUT_BUF_SIZE)
		{
		}

		/// <summary>
		/// Constructs a CipherInputStream from an InputStream and a StreamCipher.
		/// </summary>
		public CipherInputStream(InputStream @is, StreamCipher cipher) : this(@is, cipher, INPUT_BUF_SIZE)
		{
		}

		/// <summary>
		/// Constructs a CipherInputStream from an InputStream and an AEADBlockCipher.
		/// </summary>
		public CipherInputStream(InputStream @is, AEADBlockCipher cipher) : this(@is, cipher, INPUT_BUF_SIZE)
		{
		}

		/// <summary>
		/// Constructs a CipherInputStream from an InputStream, a
		/// BufferedBlockCipher, and a specified internal buffer size.
		/// </summary>
		public CipherInputStream(InputStream @is, BufferedBlockCipher cipher, int bufSize) : base(@is)
		{

			this.bufferedBlockCipher = cipher;
			this.inBuf = new byte[bufSize];
			this.skippingCipher = (cipher is SkippingCipher) ? (SkippingCipher)cipher : null;
		}

		/// <summary>
		/// Constructs a CipherInputStream from an InputStream, a StreamCipher, and a specified internal buffer size.
		/// </summary>
		public CipherInputStream(InputStream @is, StreamCipher cipher, int bufSize) : base(@is)
		{

			this.streamCipher = cipher;
			this.inBuf = new byte[bufSize];
			this.skippingCipher = (cipher is SkippingCipher) ? (SkippingCipher)cipher : null;
		}

		/// <summary>
		/// Constructs a CipherInputStream from an InputStream, an AEADBlockCipher, and a specified internal buffer size.
		/// </summary>
		public CipherInputStream(InputStream @is, AEADBlockCipher cipher, int bufSize) : base(@is)
		{

			this.aeadBlockCipher = cipher;
			this.inBuf = new byte[bufSize];
			this.skippingCipher = (cipher is SkippingCipher) ? (SkippingCipher)cipher : null;
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
				int read = @in.read(inBuf);
				if (read == -1)
				{
					finaliseCipher();
					if (maxBuf == 0)
					{
						return -1;
					}
					return maxBuf;
				}

				try
				{
					ensureCapacity(read, false);
					if (bufferedBlockCipher != null)
					{
						maxBuf = bufferedBlockCipher.processBytes(inBuf, 0, read, buf, 0);
					}
					else if (aeadBlockCipher != null)
					{
						maxBuf = aeadBlockCipher.processBytes(inBuf, 0, read, buf, 0);
					}
					else
					{
						streamCipher.processBytes(inBuf, 0, read, buf, 0);
						maxBuf = read;
					}
				}
				catch (Exception e)
				{
					throw new CipherIOException("Error processing stream ", e);
				}
			}
			return maxBuf;
		}

		private void finaliseCipher()
		{
			try
			{
				finalized = true;
				ensureCapacity(0, true);
				if (bufferedBlockCipher != null)
				{
					maxBuf = bufferedBlockCipher.doFinal(buf, 0);
				}
				else if (aeadBlockCipher != null)
				{
					maxBuf = aeadBlockCipher.doFinal(buf, 0);
				}
				else
				{
					maxBuf = 0; // a stream cipher
				}
			}
//JAVA TO C# CONVERTER WARNING: 'final' catch parameters are not available in C#:
//ORIGINAL LINE: catch (final org.bouncycastle.crypto.InvalidCipherTextException e)
			catch (InvalidCipherTextException e)
			{
				throw new InvalidCipherTextIOException("Error finalising cipher", e);
			}
			catch (Exception e)
			{
				throw new IOException("Error finalising cipher " + e);
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
		/// outputs data, and then returns up to <code>b.length</code> bytes in the provided array.
		/// <para>
		/// If the underlying stream is exhausted by this call, the cipher will be finalised.
		/// </para> </summary>
		/// <param name="b"> the buffer into which the data is read. </param>
		/// <returns> the total number of bytes read into the buffer, or <code>-1</code> if there is no
		///         more data because the end of the stream has been reached. </returns>
		/// <exception cref="IOException"> if there was an error closing the input stream. </exception>
		/// <exception cref="InvalidCipherTextIOException"> if the data read from the stream was invalid ciphertext
		/// (e.g. the cipher is an AEAD cipher and the ciphertext tag check fails). </exception>
		public virtual int read(byte[] b)
		{
			return read(b, 0, b.Length);
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

			if (skippingCipher != null)
			{
				int avail = available();
				if (n <= avail)
				{
					bufOff += (int)n;

					return n;
				}

				bufOff = maxBuf;

				long skip = @in.skip(n - avail);

				long cSkip = skippingCipher.skip(skip);

				if (skip != cSkip)
				{
					throw new IOException("Unable to skip cipher " + skip + " bytes.");
				}

				return skip + avail;
			}
			else
			{
				int skip = (int)Math.Min(n, available());
				bufOff += skip;

				return skip;
			}
		}

		public virtual int available()
		{
			return maxBuf - bufOff;
		}

		/// <summary>
		/// Ensure the cipher text buffer has space sufficient to accept an upcoming output.
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
		/// Closes the underlying input stream and finalises the processing of the data by the cipher.
		/// </summary>
		/// <exception cref="IOException"> if there was an error closing the input stream. </exception>
		/// <exception cref="InvalidCipherTextIOException"> if the data read from the stream was invalid ciphertext
		///             (e.g. the cipher is an AEAD cipher and the ciphertext tag check fails). </exception>
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
			markBufOff = 0;
			markPosition = 0;
			if (markBuf != null)
			{
				Arrays.fill(markBuf, (byte)0);
				markBuf = null;
			}
			if (buf != null)
			{
				Arrays.fill(buf, (byte)0);
				buf = null;
			}
			Arrays.fill(inBuf, (byte)0);
		}

		/// <summary>
		/// Mark the current position.
		/// <para>
		/// This method only works if markSupported() returns true - which means the underlying stream supports marking, and the cipher passed
		/// in to this stream's constructor is a SkippingCipher (so capable of being reset to an arbitrary point easily).
		/// </para> </summary>
		/// <param name="readlimit"> the maximum read ahead required before a reset() may be called. </param>
		public virtual void mark(int readlimit)
		{
			@in.mark(readlimit);
			if (skippingCipher != null)
			{
				markPosition = skippingCipher.getPosition();
			}

			if (buf != null)
			{
				markBuf = new byte[buf.Length];
				JavaSystem.arraycopy(buf, 0, markBuf, 0, buf.Length);
			}

			markBufOff = bufOff;
		}

		/// <summary>
		/// Reset to the last marked position, if supported.
		/// </summary>
		/// <exception cref="IOException"> if marking not supported by the cipher used, or the underlying stream. </exception>
		public virtual void reset()
		{
			if (skippingCipher == null)
			{
				throw new IOException("cipher must implement SkippingCipher to be used with reset()");
			}

			@in.reset();

			skippingCipher.seekTo(markPosition);

			if (markBuf != null)
			{
				buf = markBuf;
			}

			bufOff = markBufOff;
		}

		/// <summary>
		/// Return true if mark(readlimit) is supported. This will be true if the underlying stream supports marking and the
		/// cipher used is a SkippingCipher,
		/// </summary>
		/// <returns> true if mark(readlimit) supported, false otherwise. </returns>
		public virtual bool markSupported()
		{
			if (skippingCipher != null)
			{
				return @in.markSupported();
			}

			return false;
		}

	}

}