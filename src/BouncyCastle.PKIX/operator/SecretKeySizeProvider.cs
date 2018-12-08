namespace org.bouncycastle.@operator
{
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public interface SecretKeySizeProvider
	{
		int getKeySize(AlgorithmIdentifier algorithmIdentifier);

		/// <summary>
		/// Return the key size implied by the OID, if one exists.
		/// </summary>
		/// <param name="algorithm"> the OID of the algorithm of interest. </param>
		/// <returns> -1 if there is no fixed key size associated with the OID, or more information is required. </returns>
		int getKeySize(ASN1ObjectIdentifier algorithm);
	}

}