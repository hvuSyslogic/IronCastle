namespace org.bouncycastle.@operator
{
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// General finder for converting OIDs and AlgorithmIdentifiers into strings.
	/// </summary>
	public interface AlgorithmNameFinder
	{
		/// <summary>
		/// Return true if the passed in objectIdentifier has a "human friendly" name associated with it.
		/// </summary>
		/// <param name="objectIdentifier"> the OID of interest. </param>
		/// <returns> true if a name lookup exists for the OID, false otherwise. </returns>
		bool hasAlgorithmName(ASN1ObjectIdentifier objectIdentifier);

		/// <summary>
		/// Return a string representation of the passed in objectIdentifier.
		/// </summary>
		/// <param name="objectIdentifier"> the OID of interest. </param>
		/// <returns> a "human friendly" representation of the OID, the OID as a string if none available. </returns>
		string getAlgorithmName(ASN1ObjectIdentifier objectIdentifier);

		/// <summary>
		/// Return a string representation of the passed in AlgorithmIdentifier, based on the OID in the AlgorithmField, with the parameters
		/// included where appropriate.
		/// </summary>
		/// <param name="algorithmIdentifier"> the AlgorithmIdentifier of interest. </param>
		/// <returns> a "human friendly" representation of the algorithmIdentifier, the identifiers OID as a string if none available. </returns>
		string getAlgorithmName(AlgorithmIdentifier algorithmIdentifier);
	}

}