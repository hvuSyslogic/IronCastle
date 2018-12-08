namespace org.bouncycastle.jce.interfaces
{

	public interface GOST3410PrivateKey : GOST3410Key, java.security.PrivateKey
	{

		BigInteger getX();
	}

}