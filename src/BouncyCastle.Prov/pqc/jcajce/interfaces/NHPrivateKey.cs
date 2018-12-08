namespace org.bouncycastle.pqc.jcajce.interfaces
{

	public interface NHPrivateKey : NHKey, PrivateKey
	{
		short[] getSecretData();
	}

}