using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.util.io
{

	/// <summary>
	/// An input stream which copies anything read through it to another stream.
	/// </summary>
	public class TeeInputStream : InputStream
	{
		private readonly InputStream input;
		private readonly OutputStream output;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="input"> input stream to be wrapped. </param>
		/// <param name="output"> output stream to copy any input read to. </param>
		public TeeInputStream(InputStream input, OutputStream output)
		{
			this.input = input;
			this.output = output;
		}

		public virtual int read(byte[] buf)
		{
			return read(buf, 0, buf.Length);
		}

		public virtual int read(byte[] buf, int off, int len)
		{
			int i = input.read(buf, off, len);

			if (i > 0)
			{
				output.write(buf, off, i);
			}

			return i;
		}

		public virtual int read()
		{
			int i = input.read();

			if (i >= 0)
			{
				output.write(i);
			}

			return i;
		}

		public virtual void close()
		{
			this.input.close();
			this.output.close();
		}

		public virtual OutputStream getOutputStream()
		{
			return output;
		}
	}

}