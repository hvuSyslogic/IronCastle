using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.util.io
{


	/// <summary>
	/// An output stream which copies anything written into it to another stream.
	/// </summary>
	public class TeeOutputStream : OutputStream
	{
		private OutputStream output1;
		private OutputStream output2;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="output1"> the output stream that is wrapped. </param>
		/// <param name="output2"> a secondary stream that anything written to output1 is also written to. </param>
		public TeeOutputStream(OutputStream output1, OutputStream output2)
		{
			this.output1 = output1;
			this.output2 = output2;
		}

		public override void write(byte[] buf)
		{
			this.output1.write(buf);
			this.output2.write(buf);
		}

		public override void write(byte[] buf, int off, int len)
		{
			this.output1.write(buf, off, len);
			this.output2.write(buf, off, len);
		}

		public override void write(int b)
		{
			this.output1.write(b);
			this.output2.write(b);
		}

		public override void flush()
		{
			this.output1.flush();
			this.output2.flush();
		}

		public override void close()
		{
			this.output1.close();
			this.output2.close();
		}
	}
}