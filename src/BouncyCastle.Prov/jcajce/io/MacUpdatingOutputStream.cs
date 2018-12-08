namespace org.bouncycastle.jcajce.io
{

	public class MacUpdatingOutputStream : OutputStream
	{
		private Mac mac;

		public MacUpdatingOutputStream(Mac mac)
		{
			this.mac = mac;
		}

		public virtual void write(byte[] bytes, int off, int len)
		{
			mac.update(bytes, off, len);
		}

		public virtual void write(byte[] bytes)
		{
			mac.update(bytes);
		}

		public virtual void write(int b)
		{
			mac.update((byte)b);
		}
	}

}