namespace org.bouncycastle.@operator.bc
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using ExtendedDigest = org.bouncycastle.crypto.ExtendedDigest;

	public interface BcDigestProvider
	{
		ExtendedDigest get(AlgorithmIdentifier digestAlgorithmIdentifier);
	}

}