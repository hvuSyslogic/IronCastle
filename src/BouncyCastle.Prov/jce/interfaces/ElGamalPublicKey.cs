namespace org.bouncycastle.jce.interfaces
{

	public interface ElGamalPublicKey : ElGamalKey, DHPublicKey
	{
		BigInteger getY();
	}

}