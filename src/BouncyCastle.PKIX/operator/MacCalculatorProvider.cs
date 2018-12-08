namespace org.bouncycastle.@operator
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public interface MacCalculatorProvider
	{
		MacCalculator get(AlgorithmIdentifier algorithm);
	}

}