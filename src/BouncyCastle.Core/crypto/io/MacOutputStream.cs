using org.bouncycastle.Port.java.io;

namespace org.bouncycastle.crypto.io
{

	public class MacOutputStream : OutputStream
	{
		protected internal Mac mac;

		public MacOutputStream(Mac mac)
		{
			this.mac = mac;
		}

		public virtual void write(int b)
		{
			mac.update((byte)b);
		}

		public virtual void write(byte[] b, int off, int len)
		{
			mac.update(b, off, len);
		}

		public virtual byte[] getMac()
		{
			byte[] res = new byte[mac.getMacSize()];

			mac.doFinal(res, 0);

			return res;
		}
	}

}