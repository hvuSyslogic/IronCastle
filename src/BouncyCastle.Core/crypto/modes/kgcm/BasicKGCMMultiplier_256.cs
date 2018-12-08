namespace org.bouncycastle.crypto.modes.kgcm
{
	public class BasicKGCMMultiplier_256 : KGCMMultiplier
	{
		private readonly long[] H = new long[KGCMUtil_256.SIZE];

		public virtual void init(long[] H)
		{
			KGCMUtil_256.copy(H, this.H);
		}

		public virtual void multiplyH(long[] z)
		{
			KGCMUtil_256.multiply(z, H, z);
		}
	}

}