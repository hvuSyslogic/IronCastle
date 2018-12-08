namespace org.bouncycastle.mail.smime.util
{

	public class CRLFOutputStream : FilterOutputStream
	{
		protected internal int lastb;
		protected internal static byte[] newline;

		public CRLFOutputStream(OutputStream outputstream) : base(outputstream)
		{
			lastb = -1;
		}

		public virtual void write(int i)
		{
			if (i == '\r')
			{
				@out.write(newline);
			}
			else if (i == '\n')
			{
				if (lastb != '\r')
				{
					@out.write(newline);
				}
			}
			else
			{
			   @out.write(i);
			}

			lastb = i;
		}

		public virtual void write(byte[] buf)
		{
			this.write(buf, 0, buf.Length);
		}

		public virtual void write(byte[] buf, int off, int len)
		{
			for (int i = off; i != off + len; i++)
			{
				this.write(buf[i]);
			}
		}

		public virtual void writeln()
		{
			base.@out.write(newline);
		}

		static CRLFOutputStream()
		{
			newline = new byte[2];
			newline[0] = (byte)'\r';
			newline[1] = (byte)'\n';
		}
	}

}