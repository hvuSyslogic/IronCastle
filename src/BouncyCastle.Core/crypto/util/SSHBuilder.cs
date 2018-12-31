using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.util
{

	
	public class SSHBuilder
	{
		private readonly ByteArrayOutputStream bos = new ByteArrayOutputStream();

		public virtual void u32(long value)
		{
			bos.write((int)(((long)((ulong)value >> 24)) & 0xFF));
			bos.write((int)(((long)((ulong)value >> 16)) & 0xFF));
			bos.write((int)(((long)((ulong)value >> 8)) & 0xFF));
			bos.write((int)(value & 0xFF));
		}

		public virtual void rawArray(byte[] value)
		{
			u32(value.Length);
			try
			{
				bos.write(value);
			}
			catch (IOException e)
			{
				throw new RuntimeException(e.Message, e);
			}
		}

		public virtual void write(byte[] value)
		{
			try
			{
				bos.write(value);
			}
			catch (IOException e)
			{
				throw new RuntimeException(e.Message, e);
			}
		}

		public virtual void writeString(string str)
		{
			rawArray(Strings.toByteArray(str));
		}

		public virtual byte[] getBytes()
		{
			return bos.toByteArray();
		}

	}

}