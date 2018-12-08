using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.notexisting
{
	public class FilterInputStream : InputStream
	{
		protected internal InputStream @in;

		protected internal FilterInputStream(InputStream underlying)
		{
			@in = underlying;
		}

		public override int read()
		{
			return @in.read();
		}

		public override int read(byte[] b)
		{
			return read(b, 0, b.Length);
		}

		public override int read(byte[] b, int offset, int length)
		{
			return @in.read(b, offset, length);
		}

		public override long skip(long n)
		{
			return @in.skip(n);
		}

		public override int available()
		{
			return @in.available();
		}

		public override void close()
		{
			@in.close();
		}

		public override void mark(int readlimit)
		{
			@in.mark(readlimit);
		}

		public override void reset()
		{
			@in.reset();
		}

		public override bool markSupported()
		{
			return @in.markSupported();
		}
	}
}