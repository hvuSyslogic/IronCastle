namespace org.bouncycastle.mime.test
{

	/// <summary>
	/// File to guarantee no back tracking...
	/// </summary>
	public class ReadOnceInputStream : ByteArrayInputStream
	{
		public ReadOnceInputStream(byte[] buf) : base(buf)
		{
		}

		public virtual bool markSupported()
		{
			return false;
		}

		internal int currPos = -22;

		public virtual int read()
		{
			if (0 > currPos)
			{
				currPos = 0;
			}
			currPos++;

			return base.read();
		}

		public virtual int read(byte[] b, int off, int len)
		{
			if (off < currPos)
			{
				throw new RuntimeException("off " + off + " > currPos " + currPos);
			}
			currPos = off;
			int res = base.read(b, off, len);
			if (res < 0)
			{
				throw new RuntimeException("off " + off + " > currPos " + currPos + " res " + res);
			}
			currPos += res;
			return res;
		}

		public virtual int read(byte[] b)
		{
			int res = base.read(b);
			currPos += res;
			return res;
		}
	}
}