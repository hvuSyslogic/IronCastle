using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.nio.channels;

namespace org.bouncycastle.asn1
{

	public class StreamUtil
	{
		private static readonly long MAX_MEMORY = Runtime.getRuntime().maxMemory();

		/// <summary>
		/// Find out possible longest length...
		/// </summary>
		/// <param name="in"> input stream of interest </param>
		/// <returns> length calculation or MAX_VALUE. </returns>
		internal static int findLimit(InputStream @in)
		{
			if (@in is LimitedInputStream)
			{
				return ((LimitedInputStream)@in).getRemaining();
			}
			else if (@in is ASN1InputStream)
			{
				return ((ASN1InputStream)@in).getLimit();
			}
			else if (@in is ByteArrayInputStream)
			{
				return ((ByteArrayInputStream)@in).available();
			}
			else if (@in is FileInputStream)
			{
				try
				{
					FileChannel channel = ((FileInputStream)@in).getChannel();
					long size = (channel != null) ? channel.size() : int.MaxValue;

					if (size < int.MaxValue)
					{
						return (int)size;
					}
				}
				catch (IOException)
				{
					// ignore - they'll find out soon enough!
				}
			}

			if (MAX_MEMORY > int.MaxValue)
			{
				return int.MaxValue;
			}

			return (int)MAX_MEMORY;
		}

		internal static int calculateBodyLength(int length)
		{
			int count = 1;

			if (length > 127)
			{
				int size = 1;
				int val = length;

				while ((val = (int)((uint)val >> 8)) != 0)
				{
					size++;
				}

				for (int i = (size - 1) * 8; i >= 0; i -= 8)
				{
					count++;
				}
			}

			return count;
		}

		internal static int calculateTagLength(int tagNo)
		{
			int length = 1;

			if (tagNo >= 31)
			{
				if (tagNo < 128)
				{
					length++;
				}
				else
				{
					byte[] stack = new byte[5];
					int pos = stack.Length;

					stack[--pos] = (byte)(tagNo & 0x7F);

					do
					{
						tagNo >>= 7;
						stack[--pos] = unchecked((byte)(tagNo & 0x7F | 0x80));
					} while (tagNo > 127);

					length += stack.Length - pos;
				}
			}

			return length;
		}
	}

}