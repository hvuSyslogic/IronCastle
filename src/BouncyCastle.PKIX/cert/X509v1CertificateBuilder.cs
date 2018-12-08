using System;

namespace org.bouncycastle.cert
{

	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using ExtensionsGenerator = org.bouncycastle.asn1.x509.ExtensionsGenerator;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using Time = org.bouncycastle.asn1.x509.Time;
	using V1TBSCertificateGenerator = org.bouncycastle.asn1.x509.V1TBSCertificateGenerator;
	using V3TBSCertificateGenerator = org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;


	/// <summary>
	/// class to produce an X.509 Version 1 certificate.
	/// </summary>
	public class X509v1CertificateBuilder
	{
		private V1TBSCertificateGenerator tbsGen;

		/// <summary>
		/// Create a builder for a version 1 certificate.
		/// </summary>
		/// <param name="issuer"> the certificate issuer </param>
		/// <param name="serial"> the certificate serial number </param>
		/// <param name="notBefore"> the date before which the certificate is not valid </param>
		/// <param name="notAfter"> the date after which the certificate is not valid </param>
		/// <param name="subject"> the certificate subject </param>
		/// <param name="publicKeyInfo"> the info structure for the public key to be associated with this certificate. </param>
		public X509v1CertificateBuilder(X500Name issuer, BigInteger serial, DateTime notBefore, DateTime notAfter, X500Name subject, SubjectPublicKeyInfo publicKeyInfo) : this(issuer, serial, new Time(notBefore), new Time(notAfter), subject, publicKeyInfo)
		{
		}

	   /// <summary>
	   /// Create a builder for a version 1 certificate. You may need to use this constructor if the default locale
	   /// doesn't use a Gregorian calender so that the Time produced is compatible with other ASN.1 implementations.
	   /// </summary>
	   /// <param name="issuer"> the certificate issuer </param>
	   /// <param name="serial"> the certificate serial number </param>
	   /// <param name="notBefore"> the date before which the certificate is not valid </param>
	   /// <param name="notAfter"> the date after which the certificate is not valid </param>
	   /// <param name="dateLocale"> locale to be used for date interpretation. </param>
	   /// <param name="subject"> the certificate subject </param>
	   /// <param name="publicKeyInfo"> the info structure for the public key to be associated with this certificate. </param>
	   public X509v1CertificateBuilder(X500Name issuer, BigInteger serial, DateTime notBefore, DateTime notAfter, Locale dateLocale, X500Name subject, SubjectPublicKeyInfo publicKeyInfo) : this(issuer, serial, new Time(notBefore, dateLocale), new Time(notAfter, dateLocale), subject, publicKeyInfo)
	   {
	   }

	   /// <summary>
	   /// Create a builder for a version 1 certificate.
	   /// </summary>
	   /// <param name="issuer"> the certificate issuer </param>
	   /// <param name="serial"> the certificate serial number </param>
	   /// <param name="notBefore"> the Time before which the certificate is not valid </param>
	   /// <param name="notAfter"> the Time after which the certificate is not valid </param>
	   /// <param name="subject"> the certificate subject </param>
	   /// <param name="publicKeyInfo"> the info structure for the public key to be associated with this certificate. </param>
	   public X509v1CertificateBuilder(X500Name issuer, BigInteger serial, Time notBefore, Time notAfter, X500Name subject, SubjectPublicKeyInfo publicKeyInfo)
	   {
		   if (issuer == null)
		   {
			   throw new IllegalArgumentException("issuer must not be null");
		   }

		   if (publicKeyInfo == null)
		   {
			   throw new IllegalArgumentException("publicKeyInfo must not be null");
		   }

		   tbsGen = new V1TBSCertificateGenerator();
		   tbsGen.setSerialNumber(new ASN1Integer(serial));
		   tbsGen.setIssuer(issuer);
		   tbsGen.setStartDate(notBefore);
		   tbsGen.setEndDate(notAfter);
		   tbsGen.setSubject(subject);
		   tbsGen.setSubjectPublicKeyInfo(publicKeyInfo);
	   }

		/// <summary>
		/// Generate an X509 certificate, based on the current issuer and subject
		/// using the passed in signer.
		/// </summary>
		/// <param name="signer"> the content signer to be used to generate the signature validating the certificate. </param>
		/// <returns> a holder containing the resulting signed certificate. </returns>
		public virtual X509CertificateHolder build(ContentSigner signer)
		{
			tbsGen.setSignature(signer.getAlgorithmIdentifier());

			return CertUtils.generateFullCert(signer, tbsGen.generateTBSCertificate());
		}
	}
}