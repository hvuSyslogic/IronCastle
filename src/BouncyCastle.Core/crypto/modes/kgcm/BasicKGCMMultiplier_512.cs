namespace org.bouncycastle.crypto.modes.kgcm
{
	public class BasicKGCMMultiplier_512 : KGCMMultiplier
	{
		private readonly ulong[] H = new ulong[KGCMUtil_512.SIZE];

		public virtual void init(ulong[] H)
		{
			KGCMUtil_512.copy(H, this.H);
		}

		public virtual void multiplyH(ulong[] z)
		{
			KGCMUtil_512.multiply(z, H, z);
		}
	}

}