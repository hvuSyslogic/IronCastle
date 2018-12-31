namespace org.bouncycastle.crypto.modes.kgcm
{
	public interface KGCMMultiplier
	{
		void init(ulong[] H);
		void multiplyH(ulong[] z);
	}

}