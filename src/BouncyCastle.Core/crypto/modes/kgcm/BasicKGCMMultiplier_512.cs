namespace org.bouncycastle.crypto.modes.kgcm
{
	public class BasicKGCMMultiplier_512 : KGCMMultiplier
	{
		private readonly long[] H = new long[KGCMUtil_512.SIZE];

		public virtual void init(long[] H)
		{
			KGCMUtil_512.copy(H, this.H);
		}

		public virtual void multiplyH(long[] z)
		{
			KGCMUtil_512.multiply(z, H, z);
		}
	}

}