namespace org.bouncycastle.@operator
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// The base interface for a provider of DigestCalculator implementations.
	/// </summary>
	public interface DigestCalculatorProvider
	{
		DigestCalculator get(AlgorithmIdentifier digestAlgorithmIdentifier);
	}

}