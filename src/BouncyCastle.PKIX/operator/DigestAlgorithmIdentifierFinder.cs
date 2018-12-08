namespace org.bouncycastle.@operator
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public interface DigestAlgorithmIdentifierFinder
	{
		/// <summary>
		/// Find the digest algorithm identifier that matches with
		/// the passed in signature algorithm identifier.
		/// </summary>
		/// <param name="sigAlgId"> the signature algorithm of interest. </param>
		/// <returns> an algorithm identifier for the corresponding digest. </returns>
		AlgorithmIdentifier find(AlgorithmIdentifier sigAlgId);

		/// <summary>
		/// Find the algorithm identifier that matches with
		/// the passed in digest name.
		/// </summary>
		/// <param name="digAlgName"> the name of the digest algorithm of interest. </param>
		/// <returns> an algorithm identifier for the digest signature. </returns>
		AlgorithmIdentifier find(string digAlgName);
	}
}