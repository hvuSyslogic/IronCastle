namespace org.bouncycastle.jce.interfaces
{

	public interface GOST3410PublicKey : GOST3410Key, PublicKey
	{

		BigInteger getY();
	}

}