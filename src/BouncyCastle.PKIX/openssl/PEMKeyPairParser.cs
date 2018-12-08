namespace org.bouncycastle.openssl
{

	public interface PEMKeyPairParser
	{
		PEMKeyPair parse(byte[] encoding);
	}

}