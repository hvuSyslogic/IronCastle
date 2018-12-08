using System;

namespace org.bouncycastle.x509
{

	/// <summary>
	/// Interface for an X.509 Attribute Certificate. </summary>
	/// @deprecated use X509CertificateHolder class in the PKIX package. 
	public interface X509AttributeCertificate : X509Extension
	{
		/// <summary>
		/// Return the version number for the certificate.
		/// </summary>
		/// <returns> the version number. </returns>
		int getVersion();

		/// <summary>
		/// Return the serial number for the certificate.
		/// </summary>
		/// <returns> the serial number. </returns>
		BigInteger getSerialNumber();

		/// <summary>
		/// Return the date before which the certificate is not valid.
		/// </summary>
		/// <returns> the "not valid before" date. </returns>
		DateTime getNotBefore();

		/// <summary>
		/// Return the date after which the certificate is not valid.
		/// </summary>
		/// <returns> the "not valid afer" date. </returns>
		DateTime getNotAfter();

		/// <summary>
		/// Return the holder of the certificate.
		/// </summary>
		/// <returns> the holder. </returns>
		AttributeCertificateHolder getHolder();

		/// <summary>
		/// Return the issuer details for the certificate.
		/// </summary>
		/// <returns> the issuer details. </returns>
		AttributeCertificateIssuer getIssuer();

		/// <summary>
		/// Return the attributes contained in the attribute block in the certificate.
		/// </summary>
		/// <returns> an array of attributes. </returns>
		X509Attribute[] getAttributes();

		/// <summary>
		/// Return the attributes with the same type as the passed in oid.
		/// </summary>
		/// <param name="oid"> the object identifier we wish to match. </param>
		/// <returns> an array of matched attributes, null if there is no match. </returns>
		X509Attribute[] getAttributes(string oid);

		bool[] getIssuerUniqueID();

		void checkValidity();

		void checkValidity(DateTime date);

		byte[] getSignature();

		void verify(PublicKey key, string provider);

		/// <summary>
		/// Return an ASN.1 encoded byte array representing the attribute certificate.
		/// </summary>
		/// <returns> an ASN.1 encoded byte array. </returns>
		/// <exception cref="IOException"> if the certificate cannot be encoded. </exception>
		byte[] getEncoded();
	}

}