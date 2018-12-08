namespace org.bouncycastle.@operator
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;

	/// <summary>
	/// General interface for providers of ContentVerifier objects.
	/// </summary>
	public interface ContentVerifierProvider
	{
		/// <summary>
		/// Return whether or not this verifier has a certificate associated with it.
		/// </summary>
		/// <returns> true if there is an associated certificate, false otherwise. </returns>
		bool hasAssociatedCertificate();

		/// <summary>
		/// Return the associated certificate if there is one.
		/// </summary>
		/// <returns> a holder containing the associated certificate if there is one, null if there is not. </returns>
		X509CertificateHolder getAssociatedCertificate();

		/// <summary>
		/// Return a ContentVerifier that matches the passed in algorithm identifier,
		/// </summary>
		/// <param name="verifierAlgorithmIdentifier"> the algorithm and parameters required. </param>
		/// <returns> a matching ContentVerifier </returns>
		/// <exception cref="OperatorCreationException"> if the required ContentVerifier cannot be created. </exception>
		ContentVerifier get(AlgorithmIdentifier verifierAlgorithmIdentifier);
	}

}