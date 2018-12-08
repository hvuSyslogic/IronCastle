namespace org.bouncycastle.mime.encoding
{

	using Base64 = org.bouncycastle.util.encoders.Base64;

	public class Base64OutputStream : FilterOutputStream
	{
		internal byte[] buffer = new byte[54];
		internal int bufOff;

		public Base64OutputStream(OutputStream stream) : base(stream)
		{
		}

		public virtual void write(int b)
		{
			doWrite((byte)b);
		}

		public virtual void write(byte[] buf, int bufOff, int len)
		{
			for (int i = 0; i != len; i++)
			{
				doWrite(buf[bufOff + i]);
			}
		}

		public virtual void write(byte[] buf)
		{
			write(buf, 0, buf.Length);
		}

		public virtual void close()
		{
			if (bufOff > 0)
			{
				Base64.encode(buffer, 0, bufOff, @out);
			}
			@out.close();
		}

		private void doWrite(byte b)
		{
			buffer[bufOff++] = b;
			if (bufOff == buffer.Length)
			{
				Base64.encode(buffer, 0, buffer.Length, @out);
				@out.write('\r');
				@out.write('\n');
				bufOff = 0;
			}
		}
	}

}