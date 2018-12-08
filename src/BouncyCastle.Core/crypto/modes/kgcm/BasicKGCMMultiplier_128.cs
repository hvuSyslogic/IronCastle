namespace org.bouncycastle.crypto.modes.kgcm
{
	public class BasicKGCMMultiplier_128 : KGCMMultiplier
	{
		private readonly long[] H = new long[KGCMUtil_128.SIZE];

		public virtual void init(long[] H)
		{
			KGCMUtil_128.copy(H, this.H);
		}

		public virtual void multiplyH(long[] z)
		{
			KGCMUtil_128.multiply(z, H, z);
		}
	}

}