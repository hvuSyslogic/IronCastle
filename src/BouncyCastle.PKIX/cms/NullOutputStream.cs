/// 
namespace org.bouncycastle.cms
{

	public class NullOutputStream : OutputStream
	{
		public virtual void write(byte[] buf)
		{
			// do nothing
		}

		public virtual void write(byte[] buf, int off, int len)
		{
			// do nothing
		}

		public virtual void write(int b)
		{
			// do nothing
		}
	}
}