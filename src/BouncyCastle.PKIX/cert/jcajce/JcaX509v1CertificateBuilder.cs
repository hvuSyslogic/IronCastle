using System;

namespace org.bouncycastle.cert.jcajce
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

	/// <summary>
	/// JCA helper class to allow JCA objects to be used in the construction of a Version 1 certificate.
	/// </summary>
	public class JcaX509v1CertificateBuilder : X509v1CertificateBuilder
	{
		/// <summary>
		/// Initialise the builder using a PublicKey.
		/// </summary>
		/// <param name="issuer"> X500Name representing the issuer of this certificate. </param>
		/// <param name="serial"> the serial number for the certificate. </param>
		/// <param name="notBefore"> date before which the certificate is not valid. </param>
		/// <param name="notAfter"> date after which the certificate is not valid. </param>
		/// <param name="subject"> X500Name representing the subject of this certificate. </param>
		/// <param name="publicKey"> the public key to be associated with the certificate. </param>
		public JcaX509v1CertificateBuilder(X500Name issuer, BigInteger serial, DateTime notBefore, DateTime notAfter, X500Name subject, PublicKey publicKey) : base(issuer, serial, notBefore, notAfter, subject, SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()))
		{
		}

		/// <summary>
		/// Initialise the builder using X500Principal objects and a PublicKey.
		/// </summary>
		/// <param name="issuer"> principal representing the issuer of this certificate. </param>
		/// <param name="serial"> the serial number for the certificate. </param>
		/// <param name="notBefore"> date before which the certificate is not valid. </param>
		/// <param name="notAfter"> date after which the certificate is not valid. </param>
		/// <param name="subject"> principal representing the subject of this certificate. </param>
		/// <param name="publicKey"> the public key to be associated with the certificate. </param>
		public JcaX509v1CertificateBuilder(X500Principal issuer, BigInteger serial, DateTime notBefore, DateTime notAfter, X500Principal subject, PublicKey publicKey) : base(X500Name.getInstance(issuer.getEncoded()), serial, notBefore, notAfter, X500Name.getInstance(subject.getEncoded()), SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()))
		{
		}
	}

}