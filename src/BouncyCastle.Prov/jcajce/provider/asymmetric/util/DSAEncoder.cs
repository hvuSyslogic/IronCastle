namespace org.bouncycastle.jcajce.provider.asymmetric.util
{

	/// @deprecated No longer used 
	public interface DSAEncoder
	{
		byte[] encode(BigInteger r, BigInteger s);

		BigInteger[] decode(byte[] sig);
	}

}