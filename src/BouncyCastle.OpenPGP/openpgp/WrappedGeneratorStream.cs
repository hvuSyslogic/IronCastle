namespace org.bouncycastle.openpgp
{

	public class WrappedGeneratorStream : OutputStream
	{
		private readonly OutputStream _out;
		private readonly StreamGenerator _sGen;

		public WrappedGeneratorStream(OutputStream @out, StreamGenerator sGen)
		{
			_out = @out;
			_sGen = sGen;
		}
		public virtual void write(byte[] bytes)
		{
			_out.write(bytes);
		}

		public virtual void write(byte[] bytes, int offset, int length)
		{
			_out.write(bytes, offset, length);
		}

		public virtual void write(int b)
		{
			_out.write(b);
		}

		public virtual void flush()
		{
			_out.flush();
		}

		public virtual void close()
		{
			_sGen.close();
		}
	}

}