namespace org.bouncycastle.crypto.modes.kgcm
{
	public class BasicKGCMMultiplier_128 : KGCMMultiplier
	{
		private readonly ulong[] H = new ulong[KGCMUtil_128.SIZE];

		public virtual void init(ulong[] H)
		{
			KGCMUtil_128.copy(H, this.H);
		}

		public virtual void multiplyH(ulong[] z)
		{
			KGCMUtil_128.multiply(z, H, z);
		}
	}

}