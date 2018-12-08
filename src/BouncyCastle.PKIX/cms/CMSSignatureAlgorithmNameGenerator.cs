namespace org.bouncycastle.cms
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public interface CMSSignatureAlgorithmNameGenerator
	{
		/// <summary>
		/// Return the digest algorithm using one of the standard string
		/// representations rather than the algorithm object identifier (if possible).
		/// </summary>
		/// <param name="digestAlg"> the digest algorithm id. </param>
		/// <param name="encryptionAlg"> the encryption, or signing, algorithm id. </param>
		string getSignatureName(AlgorithmIdentifier digestAlg, AlgorithmIdentifier encryptionAlg);
	}

}