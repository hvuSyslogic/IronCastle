namespace org.bouncycastle.@operator
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public interface InputDecryptorProvider
	{
		InputDecryptor get(AlgorithmIdentifier algorithm);
	}

}