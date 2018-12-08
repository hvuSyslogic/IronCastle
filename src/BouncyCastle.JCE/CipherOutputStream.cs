using System;

namespace javax.crypto
{

	/// <summary>
	/// A CipherOutputStream is composed of an OutputStream and a Cipher so
	/// that write() methods first process the data before writing them out
	/// to the underlying OutputStream.  The cipher must be fully
	/// initialized before being used by a CipherOutputStream.
	/// <para>
	/// For example, if the cipher is initialized for encryption, the
	/// CipherOutputStream will attempt to encrypt data before writing out the
	/// encrypted data.
	/// </para>
	/// <para>
	/// This class adheres strictly to the semantics, especially the
	/// failure semantics, of its ancestor classes
	/// java.io.OutputStream and java.io.FilterOutputStream.  This class
	/// has exactly those methods specified in its ancestor classes, and
	/// overrides them all.  Moreover, this class catches all exceptions
	/// that are not thrown by its ancestor classes.
	/// </para>
	/// <para>
	/// It is crucial for a programmer using this class not to use
	/// methods that are not defined or overriden in this class (such as a
	/// new method or constructor that is later added to one of the super
	/// classes), because the design and implementation of those methods
	/// are unlikely to have considered security impact with regard to
	/// CipherOutputStream.
	/// 
	/// @since JCE1.2
	/// </para>
	/// </summary>
	/// <seealso cref= OutputStream </seealso>
	/// <seealso cref= FilterOutputStream </seealso>
	/// <seealso cref= Cipher </seealso>
	/// <seealso cref= CipherInputStream </seealso>
	public class CipherOutputStream : FilterOutputStream
	{
		private Cipher c;

		private byte[] oneByte = new byte[1];

		/// <summary>
		/// Constructs a CipherOutputStream from an OutputStream and a
		/// Cipher.
		/// </summary>
		public CipherOutputStream(OutputStream os, Cipher c) : base(os)
		{
			this.c = c;
		}

		/// <summary>
		/// Constructs a CipherOutputStream from an OutputStream without
		/// specifying a Cipher. This has the effect of constructing a
		/// CipherOutputStream using a NullCipher.
		/// </summary>
		public CipherOutputStream(OutputStream os) : this(os, new NullCipher())
		{
		}

		/// <summary>
		/// Writes the specified byte to this output stream.
		/// </summary>
		/// <param name="b"> the <code>byte</code>. </param>
		/// <exception cref="IOException"> if an I/O error occurs.
		/// @since JCE1.2 </exception>
		public virtual void write(int b)
		{
			oneByte[0] = (byte)b;

			byte[] bytes = c.update(oneByte, 0, 1);

			if (bytes != null)
			{
				@out.write(bytes, 0, bytes.Length);
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
		/// <exception cref="IOException"> if an I/O error occurs.
		/// @since JCE1.2 </exception>
		/// <seealso cref= #write(byte[], int, int) </seealso>
		public virtual void write(byte[] b)
		{
			write(b, 0, b.Length);
		}

		/// <summary>
		/// Writes <code>len</code> bytes from the specified byte array 
		/// starting at offset <code>off</code> to this output stream.
		/// </summary>
		/// <param name="b"> the data. </param>
		/// <param name="off"> the start offset in the data. </param>
		/// <param name="len"> the number of bytes to write. </param>
		/// <exception cref="IOException"> if an I/O error occurs.
		/// @since JCE1.2 </exception>
		public virtual void write(byte[] b, int off, int len)
		{
			byte[] bytes = c.update(b, off, len);

			if (bytes != null)
			{
				@out.write(bytes, 0, bytes.Length);
			}
		}

		/// <summary>
		/// Flushes this output stream by forcing any buffered output bytes 
		/// that have already been processed by the encapsulated cipher object
		/// to be written out.
		/// 
		/// <para>
		/// Any bytes buffered by the encapsulated cipher
		/// and waiting to be processed by it will not be written out. For example,
		/// if the encapsulated cipher is a block cipher, and the total number of
		/// bytes written using one of the <code>write</code> methods is less than
		/// the cipher's block size, no bytes will be written out.
		/// 
		/// </para>
		/// </summary>
		/// <exception cref="IOException"> if an I/O error occurs.
		/// @since JCE1.2 </exception>
		public virtual void flush()
		{
			base.flush();
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
		/// <exception cref="IOException"> if an I/O error occurs.
		/// @since JCE1.2 </exception>
		public virtual void close()
		{
			try
			{
					byte[] bytes = c.doFinal();

					if (bytes != null)
					{
						@out.write(bytes, 0, bytes.Length);
					}
			}
			catch (Exception e)
			{
				throw new IOException("Error closing stream: " + e.ToString());
			}

			flush();

			base.close();
		}
	}

}