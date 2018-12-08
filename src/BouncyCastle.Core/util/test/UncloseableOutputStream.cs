using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.util.test
{

	/// <summary>
	/// This is a testing utility class to check the property that an <seealso cref="OutputStream"/> is never
	/// closed in some particular context - typically when wrapped by another <seealso cref="OutputStream"/> that
	/// should not be forwarding its <seealso cref="OutputStream#close()"/> calls. Not needed in production code.
	/// </summary>
	public class UncloseableOutputStream : FilterOutputStream
	{
		public UncloseableOutputStream(OutputStream s) : base(s)
		{
		}

		public virtual void close()
		{
			throw new RuntimeException("close() called on UncloseableOutputStream");
		}

		public virtual void write(byte[] b, int off, int len)
		{
			@out.write(b, off, len);
		}
	}

}