using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.tls
{

	/// <summary>
	/// A queue for bytes. This file could be more optimized.
	/// </summary>
	public class ByteQueue
	{
		/// <returns> The smallest number which can be written as 2^x which is bigger than i. </returns>
		public static int nextTwoPow(int i)
		{
			/*
			 * This code is based of a lot of code I found on the Internet which mostly
			 * referenced a book called "Hacking delight".
			 */
			i |= (i >> 1);
			i |= (i >> 2);
			i |= (i >> 4);
			i |= (i >> 8);
			i |= (i >> 16);
			return i + 1;
		}

		/// <summary>
		/// The initial size for our buffer.
		/// </summary>
		private const int DEFAULT_CAPACITY = 1024;

		/// <summary>
		/// The buffer where we store our data.
		/// </summary>
		private byte[] databuf;

		/// <summary>
		/// How many bytes at the beginning of the buffer are skipped.
		/// </summary>
		private int skipped = 0;

		/// <summary>
		/// How many bytes in the buffer are valid data.
		/// </summary>
//JAVA TO C# CONVERTER NOTE: Fields cannot have the same name as methods:
		private int available_Renamed = 0;

		private bool readOnlyBuf = false;

		public ByteQueue() : this(DEFAULT_CAPACITY)
		{
		}

		public ByteQueue(int capacity)
		{
			databuf = capacity == 0 ? TlsUtils.EMPTY_BYTES : new byte[capacity];
		}

		public ByteQueue(byte[] buf, int off, int len)
		{
			this.databuf = buf;
			this.skipped = off;
			this.available_Renamed = len;
			this.readOnlyBuf = true;
		}

		/// <summary>
		/// Add some data to our buffer.
		/// </summary>
		/// <param name="buf"> A byte-array to read data from. </param>
		/// <param name="off"> How many bytes to skip at the beginning of the array. </param>
		/// <param name="len"> How many bytes to read from the array. </param>
		public virtual void addData(byte[] buf, int off, int len)
		{
			if (readOnlyBuf)
			{
				throw new IllegalStateException("Cannot add data to read-only buffer");
			}

			if ((skipped + available_Renamed + len) > databuf.Length)
			{
				int desiredSize = ByteQueue.nextTwoPow(available_Renamed + len);
				if (desiredSize > databuf.Length)
				{
					byte[] tmp = new byte[desiredSize];
					JavaSystem.arraycopy(databuf, skipped, tmp, 0, available_Renamed);
					databuf = tmp;
				}
				else
				{
					JavaSystem.arraycopy(databuf, skipped, databuf, 0, available_Renamed);
				}
				skipped = 0;
			}

			JavaSystem.arraycopy(buf, off, databuf, skipped + available_Renamed, len);
			available_Renamed += len;
		}

		/// <returns> The number of bytes which are available in this buffer. </returns>
		public virtual int available()
		{
			return available_Renamed;
		}

		/// <summary>
		/// Copy some bytes from the beginning of the data to the provided <seealso cref="OutputStream"/>.
		/// </summary>
		/// <param name="output"> The <seealso cref="OutputStream"/> to copy the bytes to. </param>
		/// <param name="length"> How many bytes to copy. </param>
		public virtual void copyTo(OutputStream output, int length)
		{
			if (length > available_Renamed)
			{
				throw new IllegalStateException("Cannot copy " + length + " bytes, only got " + available_Renamed);
			}

			output.write(databuf, skipped, length);
		}

		/// <summary>
		/// Read data from the buffer.
		/// </summary>
		/// <param name="buf">    The buffer where the read data will be copied to. </param>
		/// <param name="offset"> How many bytes to skip at the beginning of buf. </param>
		/// <param name="len">    How many bytes to read at all. </param>
		/// <param name="skip">   How many bytes from our data to skip. </param>
		public virtual void read(byte[] buf, int offset, int len, int skip)
		{
			if ((buf.Length - offset) < len)
			{
				throw new IllegalArgumentException("Buffer size of " + buf.Length + " is too small for a read of " + len + " bytes");
			}
			if ((available_Renamed - skip) < len)
			{
				throw new IllegalStateException("Not enough data to read");
			}
			JavaSystem.arraycopy(databuf, skipped + skip, buf, offset, len);
		}

		/// <summary>
		/// Return a <seealso cref="ByteArrayInputStream"/> over some bytes at the beginning of the data. </summary>
		/// <param name="length"> How many bytes will be readable. </param>
		/// <returns> A <seealso cref="ByteArrayInputStream"/> over the data. </returns>
		public virtual ByteArrayInputStream readFrom(int length)
		{
			if (length > available_Renamed)
			{
				throw new IllegalStateException("Cannot read " + length + " bytes, only got " + available_Renamed);
			}

			int position = skipped;

			available_Renamed -= length;
			skipped += length;

			return new ByteArrayInputStream(databuf, position, length);
		}

		/// <summary>
		/// Remove some bytes from our data from the beginning.
		/// </summary>
		/// <param name="i"> How many bytes to remove. </param>
		public virtual void removeData(int i)
		{
			if (i > available_Renamed)
			{
				throw new IllegalStateException("Cannot remove " + i + " bytes, only got " + available_Renamed);
			}

			/*
			 * Skip the data.
			 */
			available_Renamed -= i;
			skipped += i;
		}

		/// <summary>
		/// Remove data from the buffer.
		/// </summary>
		/// <param name="buf"> The buffer where the removed data will be copied to. </param>
		/// <param name="off"> How many bytes to skip at the beginning of buf. </param>
		/// <param name="len"> How many bytes to read at all. </param>
		/// <param name="skip"> How many bytes from our data to skip. </param>
		public virtual void removeData(byte[] buf, int off, int len, int skip)
		{
			read(buf, off, len, skip);
			removeData(skip + len);
		}

		public virtual byte[] removeData(int len, int skip)
		{
			byte[] buf = new byte[len];
			removeData(buf, 0, len, skip);
			return buf;
		}

		public virtual void shrink()
		{
			if (available_Renamed == 0)
			{
				databuf = TlsUtils.EMPTY_BYTES;
				skipped = 0;
			}
			else
			{
				int desiredSize = ByteQueue.nextTwoPow(available_Renamed);
				if (desiredSize < databuf.Length)
				{
					byte[] tmp = new byte[desiredSize];
					JavaSystem.arraycopy(databuf, skipped, tmp, 0, available_Renamed);
					databuf = tmp;
					skipped = 0;
				}
			}
		}
	}

}