using System.IO;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.util.io
{

	/// <summary>
	/// Utility methods to assist with stream processing.
	/// </summary>
	public sealed class Streams
	{
		private static int BUFFER_SIZE = 4096;

		/// <summary>
		/// Read stream till EOF is encountered.
		/// </summary>
		/// <param name="inStr"> stream to be emptied. </param>
		/// <exception cref="IOException"> in case of underlying IOException. </exception>
		public static void drain(InputStream inStr)
		{
			byte[] bs = new byte[BUFFER_SIZE];
			while (inStr.read(bs, 0, bs.Length) >= 0)
			{
			}
		}

		/// <summary>
		/// Read stream fully, returning contents in a byte array.
		/// </summary>
		/// <param name="inStr"> stream to be read. </param>
		/// <returns> a byte array representing the contents of inStr. </returns>
		/// <exception cref="IOException"> in case of underlying IOException. </exception>
		public static byte[] readAll(InputStream inStr)
		{
			ByteArrayOutputStream buf = new ByteArrayOutputStream();
			pipeAll(inStr, buf);
			return buf.toByteArray();
		}

		/// <summary>
		/// Read from inStr up to a maximum number of bytes, throwing an exception if more the maximum amount
		/// of requested data is available.
		/// </summary>
		/// <param name="inStr"> stream to be read. </param>
		/// <param name="limit"> maximum number of bytes that can be read. </param>
		/// <returns> a byte array representing the contents of inStr. </returns>
		/// <exception cref="IOException"> in case of underlying IOException, or if limit is reached on inStr still has data in it. </exception>
		public static byte[] readAllLimited(InputStream inStr, int limit)
		{
			ByteArrayOutputStream buf = new ByteArrayOutputStream();
			pipeAllLimited(inStr, limit, buf);
			return buf.toByteArray();
		}

		/// <summary>
		/// Fully read in buf's length in data, or up to EOF, whichever occurs first,
		/// </summary>
		/// <param name="inStr"> the stream to be read. </param>
		/// <param name="buf"> the buffer to be read into. </param>
		/// <returns> the number of bytes read into the buffer. </returns>
		/// <exception cref="IOException"> in case of underlying IOException. </exception>
		public static int readFully(InputStream inStr, byte[] buf)
		{
			return readFully(inStr, buf, 0, buf.Length);
		}

		/// <summary>
		/// Fully read in len's bytes of data into buf, or up to EOF, whichever occurs first,
		/// </summary>
		/// <param name="inStr"> the stream to be read. </param>
		/// <param name="buf"> the buffer to be read into. </param>
		/// <param name="off"> offset into buf to start putting bytes into. </param>
		/// <param name="len">  the number of bytes to be read. </param>
		/// <returns> the number of bytes read into the buffer. </returns>
		/// <exception cref="IOException"> in case of underlying IOException. </exception>
		public static int readFully(InputStream inStr, byte[] buf, int off, int len)
		{
			int totalRead = 0;
			while (totalRead < len)
			{
				int numRead = inStr.read(buf, off + totalRead, len - totalRead);
				if (numRead < 0)
				{
					break;
				}
				totalRead += numRead;
			}
			return totalRead;
		}

		/// <summary>
		/// Write the full contents of inStr to the destination stream outStr.
		/// </summary>
		/// <param name="inStr"> source input stream. </param>
		/// <param name="outStr"> destination output stream. </param>
		/// <exception cref="IOException"> in case of underlying IOException. </exception>
		public static void pipeAll(InputStream inStr, OutputStream outStr)
		{
			byte[] bs = new byte[BUFFER_SIZE];
			int numRead;
			while ((numRead = inStr.read(bs, 0, bs.Length)) >= 0)
			{
				outStr.write(bs, 0, numRead);
			}
		}

		/// <summary>
		/// Write up to limit bytes of data from inStr to the destination stream outStr.
		/// </summary>
		/// <param name="inStr"> source input stream. </param>
		/// <param name="limit"> the maximum number of bytes allowed to be read. </param>
		/// <param name="outStr"> destination output stream. </param>
		/// <exception cref="IOException"> in case of underlying IOException, or if limit is reached on inStr still has data in it. </exception>
		public static long pipeAllLimited(InputStream inStr, long limit, OutputStream outStr)
		{
			long total = 0;
			byte[] bs = new byte[BUFFER_SIZE];
			int numRead;
			while ((numRead = inStr.read(bs, 0, bs.Length)) >= 0)
			{
				if ((limit - total) < numRead)
				{
					throw new StreamOverflowException("Data Overflow");
				}
				total += numRead;
				outStr.write(bs, 0, numRead);
			}
			return total;
		}

		public static void writeBufTo(ByteArrayOutputStream buf, OutputStream output)
		{
			buf.writeTo(output);
		}
	}

}