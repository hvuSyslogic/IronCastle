namespace org.bouncycastle.pqc.jcajce.interfaces
{

	public interface NHPublicKey : NHKey, PublicKey
	{
		byte[] getPublicData();
	}

}