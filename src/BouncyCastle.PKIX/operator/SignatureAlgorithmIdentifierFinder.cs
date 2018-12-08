namespace org.bouncycastle.@operator
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public interface SignatureAlgorithmIdentifierFinder
	{
		/// <summary>
		/// Find the signature algorithm identifier that matches with
		/// the passed in signature algorithm name.
		/// </summary>
		/// <param name="sigAlgName"> the name of the signature algorithm of interest. </param>
		/// <returns> an algorithm identifier for the corresponding signature. </returns>
		AlgorithmIdentifier find(string sigAlgName);
	}
}