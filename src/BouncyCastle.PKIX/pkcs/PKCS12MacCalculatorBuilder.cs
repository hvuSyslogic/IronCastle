namespace org.bouncycastle.pkcs
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;

	public interface PKCS12MacCalculatorBuilder
	{
		MacCalculator build(char[] password);

		AlgorithmIdentifier getDigestAlgorithmIdentifier();
	}

}