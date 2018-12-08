namespace org.bouncycastle.cert.crmf
{
	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;

	/// <summary>
	/// Generic interface for a CertificateRequestMessage control value.
	/// </summary>
	public interface Control
	{
		/// <summary>
		/// Return the type of this control.
		/// </summary>
		/// <returns> an ASN1ObjectIdentifier representing the type. </returns>
		ASN1ObjectIdentifier getType();

		/// <summary>
		/// Return the value contained in this control object.
		/// </summary>
		/// <returns> the value of the control. </returns>
		ASN1Encodable getValue();
	}

}