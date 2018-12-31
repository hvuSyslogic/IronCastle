using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.util
{

	
	/// <summary>
	/// A Buffer for dealing with SSH key products.
	/// </summary>
	public class SSHBuffer
	{
		private readonly byte[] buffer;
		private int pos = 0;

		public SSHBuffer(byte[] magic, byte[] buffer)
		{
			this.buffer = buffer;
			for (int i = 0; i != magic.Length; i++)
			{
				if (magic[i] != buffer[i])
				{
					throw new IllegalArgumentException("magic-number incorrect");
				}
			}

			pos += magic.Length;
		}

		public SSHBuffer(byte[] buffer)
		{
			this.buffer = buffer;
		}

		public virtual int readU32()
		{
			if (pos + 4 > buffer.Length)
			{
				throw new IllegalArgumentException("4 bytes for U32 exceeds buffer.");
			}

			int i = (buffer[pos++] & 0xFF) << 24;
			i |= (buffer[pos++] & 0xFF) << 16;
			i |= (buffer[pos++] & 0xFF) << 8;
			i |= (buffer[pos++] & 0xFF);

			return i;
		}

		public virtual byte[] readString()
		{
			int len = readU32();
			if (len == 0)
			{
				return new byte[0];
			}

			if (pos + len > buffer.Length)
			{
				throw new IllegalArgumentException("not enough data for string");
			}

			return Arrays.copyOfRange(buffer, pos, pos += len);
		}

		public virtual byte[] readPaddedString()
		{
			int len = readU32();
			if (len == 0)
			{
				return new byte[0];
			}

			if (pos + len > buffer.Length)
			{
				throw new IllegalArgumentException("not enough data for string");
			}

			return Arrays.copyOfRange(buffer, pos, pos += (len - (buffer[pos + len - 1] & 0xff)));
		}


		public virtual BigInteger positiveBigNum()
		{
			int len = readU32();
			if (pos + len > buffer.Length)
			{
				throw new IllegalArgumentException("not enough data for big num");
			}

			byte[] d = new byte[len];
			JavaSystem.arraycopy(buffer, pos, d, 0, d.Length);
			pos += len;
			return new BigInteger(1, d);
		}

		public virtual byte[] getBuffer()
		{
			return Arrays.clone(buffer);
		}

		public virtual bool hasRemaining()
		{
			return pos < buffer.Length;
		}
	}

}