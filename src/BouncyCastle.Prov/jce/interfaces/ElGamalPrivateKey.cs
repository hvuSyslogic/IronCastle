namespace org.bouncycastle.jce.interfaces
{

	public interface ElGamalPrivateKey : ElGamalKey, DHPrivateKey
	{
		BigInteger getX();
	}

}