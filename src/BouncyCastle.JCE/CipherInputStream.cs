﻿using System;

namespace javax.crypto
{

	/// <summary>
	/// A CipherInputStream is composed of an InputStream and a Cipher so
	/// that read() methods return data that are read in from the
	/// underlying InputStream but have been additionally processed by the
	/// Cipher.  The Cipher must be fully initialized before being used by
	/// a CipherInputStream.
	/// <para>
	/// For example, if the Cipher is initialized for decryption, the
	/// CipherInputStream will attempt to read in data and decrypt them,
	/// before returning the decrypted data.
	/// </para>
	/// <para>
	/// This class adheres strictly to the semantics, especially the
	/// failure semantics, of its ancestor classes
	/// java.io.FilterInputStream and java.io.InputStream.  This class has
	/// exactly those methods specified in its ancestor classes, and
	/// overrides them all.  Moreover, this class catches all exceptions
	/// that are not thrown by its ancestor classes.  In particular, the
	/// <code>skip</code> method skips, and the <code>available</code>
	/// method counts only data that have been processed by the encapsulated Cipher.
	/// </para>
	/// <para>
	/// It is crucial for a programmer using this class not to use
	/// methods that are not defined or overriden in this class (such as a
	/// new method or constructor that is later added to one of the super
	/// classes), because the design and implementation of those methods
	/// are unlikely to have considered security impact with regard to
	/// CipherInputStream.
	/// 
	/// @since JCE1.2
	/// </para>
	/// </summary>
	/// <seealso cref= InputStream </seealso>
	/// <seealso cref= FilterInputStream </seealso>
	/// <seealso cref= Cipher </seealso>
	/// <seealso cref= CipherOutputStream </seealso>
	public class CipherInputStream : FilterInputStream
	{
		private Cipher c;

		private byte[] buf;
		private byte[] inBuf;

		private int bufOff;
		private int maxBuf;
		private bool finalized;

		private const int INPUT_BUF_SIZE = 2048;

		/// <summary>
		/// Constructs a CipherInputStream from an InputStream and a
		/// Cipher.
		/// </summary>
		public CipherInputStream(InputStream @is, Cipher c) : base(@is)
		{

			this.c = c;

			buf = new byte[c.getOutputSize(INPUT_BUF_SIZE)];
			inBuf = new byte[INPUT_BUF_SIZE];
		}

		/// <summary>
		/// Constructs a CipherInputStream from an InputStream without
		/// specifying a Cipher. This has the effect of constructing a
		/// CipherInputStream using a NullCipher.
		/// </summary>
		public CipherInputStream(InputStream @is) : this(@is, new NullCipher())
		{
		}

		/// <summary>
		/// grab the next chunk of input from the underlying input stream
		/// </summary>
		private int nextChunk()
		{
			int available = base.available();

			// must always try to read 1 byte!
			// some buggy InputStreams return < 0!
			if (available <= 0)
			{
				available = 1;
			}

			if (available > inBuf.Length)
			{
				available = base.read(inBuf, 0, inBuf.Length);
			}
			else
			{
				available = base.read(inBuf, 0, available);
			}

			if (available < 0)
			{
				if (finalized)
				{
					return -1;
				}

				try
				{
					buf = c.doFinal();
				}
				catch (Exception e)
				{
					throw new IOException("error processing stream: " + e.ToString());
				}

				bufOff = 0;

				if (buf != null)
				{
					maxBuf = buf.Length;
				}
				else
				{
					maxBuf = 0;
				}

				finalized = true;

				if (bufOff == maxBuf)
				{
					return -1;
				}
			}
			else
			{
				bufOff = 0;

				try
				{
					maxBuf = c.update(inBuf, 0, available, buf, 0);
				}
				catch (Exception e)
				{
					throw new IOException("error processing stream: " + e.ToString());
				}

				if (maxBuf == 0) // not enough bytes read for first block...
				{
					return nextChunk();
				}
			}

			return maxBuf;
		}

		/// <summary>
		/// Reads the next byte of data from this input stream. The value 
		/// byte is returned as an <code>int</code> in the range 
		/// <code>0</code> to <code>255</code>. If no byte is available 
		/// because the end of the stream has been reached, the value 
		/// <code>-1</code> is returned. This method blocks until input data 
		/// is available, the end of the stream is detected, or an exception 
		/// is thrown. 
		/// </summary>
		/// <returns> the next byte of data, or <code>-1</code> if the end of the
		/// stream is reached. </returns>
		/// <exception cref="IOException"> if an I/O error occurs.
		/// @since JCE1.2 </exception>
		public virtual int read()
		{
			if (bufOff == maxBuf)
			{
				if (nextChunk() < 0)
				{
					return -1;
				}
			}

			return buf[bufOff++] & 0xff;
		}

		/// <summary>
		/// Reads up to <code>b.length</code> bytes of data from this input 
		/// stream into an array of bytes. 
		/// <para>
		/// The <code>read</code> method of <code>InputStream</code> calls 
		/// the <code>read</code> method of three arguments with the arguments 
		/// <code>b</code>, <code>0</code>, and <code>b.length</code>.
		/// 
		/// </para>
		/// </summary>
		/// <param name="b"> the buffer into which the data is read. </param>
		/// <returns> the total number of bytes read into the buffer, or
		/// <code>-1</code> is there is no more data because the end of
		/// the stream has been reached. </returns>
		/// <exception cref="IOException"> if an I/O error occurs.
		/// @since JCE1.2 </exception>
		/// <seealso cref= #read(byte[], int, int) </seealso>
		public virtual int read(byte[] b)
		{
			return read(b, 0, b.Length);
		}

		/// <summary>
		/// Reads up to <code>len</code> bytes of data from this input stream 
		/// into an array of bytes. This method blocks until some input is 
		/// available. If the first argument is <code>null,</code> up to 
		/// <code>len</code> bytes are read and discarded.
		/// </summary>
		/// <param name="b"> the buffer into which the data is read. </param>
		/// <param name="off"> the start offset of the data. </param>
		/// <param name="len"> the maximum number of bytes read. </param>
		/// <returns> the total number of bytes read into the buffer, or <code>-1</code>
		/// if there is no more data because the end of the stream has been reached. </returns>
		/// <exception cref="IOException"> if an I/O error occurs.
		/// @since JCE1.2 </exception>
		/// <seealso cref= #read() </seealso>
		public virtual int read(byte[] b, int off, int len)
		{
			if (bufOff == maxBuf)
			{
				if (nextChunk() < 0)
				{
					return -1;
				}
			}

			int available = maxBuf - bufOff;

			if (len > available)
			{
				JavaSystem.arraycopy(buf, bufOff, b, off, available);
				bufOff = maxBuf;

				return available;
			}
			else
			{
				JavaSystem.arraycopy(buf, bufOff, b, off, len);
				bufOff += len;

				return len;
			}
		}

		/// <summary>
		/// Skips <code>n</code> bytes of input from the bytes that can be read
		/// from this input stream without blocking.
		/// <para>
		/// Fewer bytes than requested might be skipped.
		/// The actual number of bytes skipped is equal to <code>n</code> or
		/// the result of a call to <a href = "#available()"><code>available</code></a>,
		/// whichever is smaller.
		/// If <code>n</code> is less than zero, no bytes are skipped.
		/// </para>
		/// <para>
		/// The actual number of bytes skipped is returned.
		/// 
		/// </para>
		/// </summary>
		/// <param name="n"> the number of bytes to be skipped. </param>
		/// <returns> the actual number of bytes skipped. </returns>
		/// <exception cref="IOException"> if an I/O error occurs.
		/// @since JCE1.2 </exception>
		public virtual long skip(long n)
		{
			if (n <= 0)
			{
				return 0;
			}

			int available = maxBuf - bufOff;

			if (n > available)
			{
				bufOff = maxBuf;

				return available;
			}
			else
			{
				bufOff += (int)n;

				return (int)n;
			}
		}

		/// <summary>
		/// Returns the number of bytes that can be read from this input 
		/// stream without blocking. The <code>available</code> method of 
		/// <code>InputStream</code> returns <code>0</code>. This method 
		/// <B>should</B> be overridden by subclasses.
		/// </summary>
		/// <returns> the number of bytes that can be read from this input stream
		/// without blocking. </returns>
		/// <exception cref="IOException"> if an I/O error occurs.
		/// @since JCE1.2 </exception>
		public virtual int available()
		{
			return maxBuf - bufOff;
		}

		/// <summary>
		/// Closes this input stream and releases any system resources 
		/// associated with the stream. 
		/// <para>
		/// The <code>close</code> method of <code>CipherInputStream</code>
		/// calls the <code>close</code> method of its underlying input
		/// stream.
		/// 
		/// </para>
		/// </summary>
		/// <exception cref="IOException"> if an I/O error occurs.
		/// @since JCE1.2 </exception>
		public virtual void close()
		{
			if (!finalized)
			{
				finalized = true;
				try
				{
					c.doFinal();
				}
				catch (Exception e)
				{
					throw new IOException("error processing stream: " + e.ToString());
				}
			}
			base.close();
		}

		/// <summary>
		/// Tests if this input stream supports the <code>mark</code> 
		/// and <code>reset</code> methods, which it does not.
		/// </summary>
		/// <returns> <code>false</code>, since this class does not support the
		/// <code>mark</code> and <code>reset</code> methods.
		/// @since JCE1.2 </returns>
		/// <seealso cref= #mark(int) </seealso>
		/// <seealso cref= #reset() </seealso>
		public virtual bool markSupported()
		{
			return false;
		}
	}

}