namespace org.bouncycastle.@operator
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public interface KeyWrapper
	{
		AlgorithmIdentifier getAlgorithmIdentifier();

		byte[] generateWrappedKey(GenericKey encryptionKey);
	}

}