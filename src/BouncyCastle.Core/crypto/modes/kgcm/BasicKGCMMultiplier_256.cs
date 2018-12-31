namespace org.bouncycastle.crypto.modes.kgcm
{
	public class BasicKGCMMultiplier_256 : KGCMMultiplier
	{
		private readonly ulong[] H = new ulong[KGCMUtil_256.SIZE];
        
		public virtual void init(ulong[] H)
		{
			KGCMUtil_256.copy(H, this.H);
		}

		public virtual void multiplyH(ulong[] z)
		{
			KGCMUtil_256.multiply(z, H, z);
		}
	}

}