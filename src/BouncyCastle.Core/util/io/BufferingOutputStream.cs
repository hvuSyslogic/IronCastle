using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.util.io
{

	/// <summary>
	/// An output stream that buffers data to be feed into an encapsulated output stream.
	/// <para>
	/// The stream zeroes out the internal buffer on each flush.
	/// </para>
	/// </summary>
	public class BufferingOutputStream : OutputStream
	{
		private readonly OutputStream other;
		private readonly byte[] buf;

		private int bufOff;

		/// <summary>
		/// Create a buffering stream with the default buffer size (4096).
		/// </summary>
		/// <param name="other"> output stream to be wrapped. </param>
		public BufferingOutputStream(OutputStream other)
		{
			this.other = other;
			this.buf = new byte[4096];
		}

		/// <summary>
		/// Create a buffering stream with a specified buffer size.
		/// </summary>
		/// <param name="other"> output stream to be wrapped. </param>
		/// <param name="bufferSize"> size in bytes for internal buffer. </param>
		public BufferingOutputStream(OutputStream other, int bufferSize)
		{
			this.other = other;
			this.buf = new byte[bufferSize];
		}

		public virtual void write(byte[] bytes, int offset, int len)
		{
			if (len < buf.Length - bufOff)
			{
				JavaSystem.arraycopy(bytes, offset, buf, bufOff, len);
				bufOff += len;
			}
			else
			{
				int gap = buf.Length - bufOff;

				JavaSystem.arraycopy(bytes, offset, buf, bufOff, gap);
				bufOff += gap;

				flush();

				offset += gap;
				len -= gap;
				while (len >= buf.Length)
				{
					other.write(bytes, offset, buf.Length);
					offset += buf.Length;
					len -= buf.Length;
				}

				if (len > 0)
				{
					JavaSystem.arraycopy(bytes, offset, buf, bufOff, len);
					bufOff += len;
				}
			}
		}

		public virtual void write(int b)
		{
			buf[bufOff++] = (byte)b;
			if (bufOff == buf.Length)
			{
				flush();
			}
		}

		/// <summary>
		/// Flush the internal buffer to the encapsulated output stream. Zero the buffer contents when done.
		/// </summary>
		/// <exception cref="IOException"> on error. </exception>
		public virtual void flush()
		{
			other.write(buf, 0, bufOff);
			bufOff = 0;
			Arrays.fill(buf, (byte)0);
		}

		public virtual void close()
		{
			flush();
			other.close();
		}
	}

}