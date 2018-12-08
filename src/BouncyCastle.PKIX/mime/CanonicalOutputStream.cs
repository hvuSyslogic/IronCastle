namespace org.bouncycastle.mime
{

	using SMimeParserContext = org.bouncycastle.mime.smime.SMimeParserContext;

	public class CanonicalOutputStream : FilterOutputStream
	{
		protected internal int lastb;
		protected internal static byte[] newline;
		private readonly bool is7Bit;

		public CanonicalOutputStream(SMimeParserContext parserContext, Headers headers, OutputStream outputstream) : base(outputstream)
		{
			lastb = -1;
			// TODO: eventually may need to handle multiparts with binary...
			if (!string.ReferenceEquals(headers.getContentType(), null))
			{
				is7Bit = !string.ReferenceEquals(headers.getContentType(), null) && !headers.getContentType().Equals("binary");
			}
			else
			{
				is7Bit = parserContext.getDefaultContentTransferEncoding().Equals("7bit");
			}
		}

		public virtual void write(int i)
		{
			if (is7Bit)
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

		static CanonicalOutputStream()
		{
			newline = new byte[2];
			newline[0] = (byte)'\r';
			newline[1] = (byte)'\n';
		}
	}

}