namespace org.bouncycastle.crypto.modes.gcm
{
	public class BasicGCMMultiplier : GCMMultiplier
	{
		private ulong[] H;

		public virtual void init(byte[] H)
		{
			this.H = GCMUtil.asLongs(H);
		}

		public virtual void multiplyH(byte[] x)
		{
			ulong[] t = GCMUtil.asLongs(x);
			GCMUtil.multiply(t, H);
			GCMUtil.asBytes(t, x);
		}
	}

}