namespace org.bouncycastle.pkcs
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public interface PKCS12MacCalculatorBuilderProvider
	{
		PKCS12MacCalculatorBuilder get(AlgorithmIdentifier algorithmIdentifier);
	}

}