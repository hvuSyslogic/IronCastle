using System;

namespace org.bouncycastle.cert.jcajce
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using Time = org.bouncycastle.asn1.x509.Time;

	/// <summary>
	/// JCA helper class to allow JCA objects to be used in the construction of a Version 3 certificate.
	/// </summary>
	public class JcaX509v3CertificateBuilder : X509v3CertificateBuilder
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
		public JcaX509v3CertificateBuilder(X500Name issuer, BigInteger serial, DateTime notBefore, DateTime notAfter, X500Name subject, PublicKey publicKey) : base(issuer, serial, notBefore, notAfter, subject, SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()))
		{
		}

		/// <summary>
		/// Initialise the builder using a PublicKey.
		/// </summary>
		/// <param name="issuer"> X500Name representing the issuer of this certificate. </param>
		/// <param name="serial"> the serial number for the certificate. </param>
		/// <param name="notBefore"> Time before which the certificate is not valid. </param>
		/// <param name="notAfter"> Time after which the certificate is not valid. </param>
		/// <param name="subject"> X500Name representing the subject of this certificate. </param>
		/// <param name="publicKey"> the public key to be associated with the certificate. </param>
		public JcaX509v3CertificateBuilder(X500Name issuer, BigInteger serial, Time notBefore, Time notAfter, X500Name subject, PublicKey publicKey) : base(issuer, serial, notBefore, notAfter, subject, SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()))
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
		public JcaX509v3CertificateBuilder(X500Principal issuer, BigInteger serial, DateTime notBefore, DateTime notAfter, X500Principal subject, PublicKey publicKey) : base(X500Name.getInstance(issuer.getEncoded()), serial, notBefore, notAfter, X500Name.getInstance(subject.getEncoded()), SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()))
		{
		}

		/// <summary>
		/// Initialise the builder using the subject from the passed in issuerCert as the issuer, as well as
		/// passing through and converting the other objects provided.
		/// </summary>
		/// <param name="issuerCert"> certificate who's subject is the issuer of the certificate we are building. </param>
		/// <param name="serial"> the serial number for the certificate. </param>
		/// <param name="notBefore"> date before which the certificate is not valid. </param>
		/// <param name="notAfter"> date after which the certificate is not valid. </param>
		/// <param name="subject"> principal representing the subject of this certificate. </param>
		/// <param name="publicKey"> the public key to be associated with the certificate. </param>
		public JcaX509v3CertificateBuilder(X509Certificate issuerCert, BigInteger serial, DateTime notBefore, DateTime notAfter, X500Principal subject, PublicKey publicKey) : this(issuerCert.getSubjectX500Principal(), serial, notBefore, notAfter, subject, publicKey)
		{
		}

		/// <summary>
		/// Initialise the builder using the subject from the passed in issuerCert as the issuer, as well as
		/// passing through and converting the other objects provided.
		/// </summary>
		/// <param name="issuerCert"> certificate who's subject is the issuer of the certificate we are building. </param>
		/// <param name="serial"> the serial number for the certificate. </param>
		/// <param name="notBefore"> date before which the certificate is not valid. </param>
		/// <param name="notAfter"> date after which the certificate is not valid. </param>
		/// <param name="subject"> principal representing the subject of this certificate. </param>
		/// <param name="publicKey"> the public key to be associated with the certificate. </param>
		public JcaX509v3CertificateBuilder(X509Certificate issuerCert, BigInteger serial, DateTime notBefore, DateTime notAfter, X500Name subject, PublicKey publicKey) : this(X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded()), serial, notBefore, notAfter, subject, publicKey)
		{
		}

		/// <summary>
		/// Add a given extension field for the standard extensions tag (tag 3)
		/// copying the extension value from another certificate.
		/// </summary>
		/// <param name="oid"> the type of the extension to be copied. </param>
		/// <param name="critical"> true if the extension is to be marked critical, false otherwise. </param>
		/// <param name="certificate"> the source of the extension to be copied. </param>
		/// <returns> the builder instance. </returns>
		public virtual JcaX509v3CertificateBuilder copyAndAddExtension(ASN1ObjectIdentifier oid, bool critical, X509Certificate certificate)
		{
			this.copyAndAddExtension(oid, critical, new JcaX509CertificateHolder(certificate));

			return this;
		}
	}

}