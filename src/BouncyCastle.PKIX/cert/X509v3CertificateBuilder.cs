using System;

namespace org.bouncycastle.cert
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using ExtensionsGenerator = org.bouncycastle.asn1.x509.ExtensionsGenerator;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using Time = org.bouncycastle.asn1.x509.Time;
	using V3TBSCertificateGenerator = org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;


	/// <summary>
	/// class to produce an X.509 Version 3 certificate.
	/// </summary>
	public class X509v3CertificateBuilder
	{
		private V3TBSCertificateGenerator tbsGen;
		private ExtensionsGenerator extGenerator;

		/// <summary>
		/// Create a builder for a version 3 certificate.
		/// </summary>
		/// <param name="issuer"> the certificate issuer </param>
		/// <param name="serial"> the certificate serial number </param>
		/// <param name="notBefore"> the date before which the certificate is not valid </param>
		/// <param name="notAfter"> the date after which the certificate is not valid </param>
		/// <param name="subject"> the certificate subject </param>
		/// <param name="publicKeyInfo"> the info structure for the public key to be associated with this certificate. </param>
		public X509v3CertificateBuilder(X500Name issuer, BigInteger serial, DateTime notBefore, DateTime notAfter, X500Name subject, SubjectPublicKeyInfo publicKeyInfo) : this(issuer, serial, new Time(notBefore), new Time(notAfter), subject, publicKeyInfo)
		{
		}

		/// <summary>
		/// Create a builder for a version 3 certificate. You may need to use this constructor if the default locale
		/// doesn't use a Gregorian calender so that the Time produced is compatible with other ASN.1 implementations.
		/// </summary>
		/// <param name="issuer"> the certificate issuer </param>
		/// <param name="serial"> the certificate serial number </param>
		/// <param name="notBefore"> the date before which the certificate is not valid </param>
		/// <param name="notAfter"> the date after which the certificate is not valid </param>
		/// <param name="dateLocale"> locale to be used for date interpretation. </param>
		/// <param name="subject"> the certificate subject </param>
		/// <param name="publicKeyInfo"> the info structure for the public key to be associated with this certificate. </param>
		public X509v3CertificateBuilder(X500Name issuer, BigInteger serial, DateTime notBefore, DateTime notAfter, Locale dateLocale, X500Name subject, SubjectPublicKeyInfo publicKeyInfo) : this(issuer, serial, new Time(notBefore, dateLocale), new Time(notAfter, dateLocale), subject, publicKeyInfo)
		{
		}

		/// <summary>
		/// Create a builder for a version 3 certificate.
		/// </summary>
		/// <param name="issuer"> the certificate issuer </param>
		/// <param name="serial"> the certificate serial number </param>
		/// <param name="notBefore"> the Time before which the certificate is not valid </param>
		/// <param name="notAfter"> the Time after which the certificate is not valid </param>
		/// <param name="subject"> the certificate subject </param>
		/// <param name="publicKeyInfo"> the info structure for the public key to be associated with this certificate. </param>
		public X509v3CertificateBuilder(X500Name issuer, BigInteger serial, Time notBefore, Time notAfter, X500Name subject, SubjectPublicKeyInfo publicKeyInfo)
		{
			tbsGen = new V3TBSCertificateGenerator();
			tbsGen.setSerialNumber(new ASN1Integer(serial));
			tbsGen.setIssuer(issuer);
			tbsGen.setStartDate(notBefore);
			tbsGen.setEndDate(notAfter);
			tbsGen.setSubject(subject);
			tbsGen.setSubjectPublicKeyInfo(publicKeyInfo);

			extGenerator = new ExtensionsGenerator();
		}

		/// <summary>
		/// Set the subjectUniqueID - note: it is very rare that it is correct to do this.
		/// </summary>
		/// <param name="uniqueID"> a boolean array representing the bits making up the subjectUniqueID. </param>
		/// <returns> this builder object. </returns>
		public virtual X509v3CertificateBuilder setSubjectUniqueID(bool[] uniqueID)
		{
			tbsGen.setSubjectUniqueID(CertUtils.booleanToBitString(uniqueID));

			return this;
		}

		/// <summary>
		/// Set the issuerUniqueID - note: it is very rare that it is correct to do this.
		/// </summary>
		/// <param name="uniqueID"> a boolean array representing the bits making up the issuerUniqueID. </param>
		/// <returns> this builder object. </returns>
		public virtual X509v3CertificateBuilder setIssuerUniqueID(bool[] uniqueID)
		{
			tbsGen.setIssuerUniqueID(CertUtils.booleanToBitString(uniqueID));

			return this;
		}

		/// <summary>
		/// Add a given extension field for the standard extensions tag (tag 3)
		/// </summary>
		/// <param name="oid"> the OID defining the extension type. </param>
		/// <param name="isCritical"> true if the extension is critical, false otherwise. </param>
		/// <param name="value"> the ASN.1 structure that forms the extension's value. </param>
		/// <returns> this builder object. </returns>
		public virtual X509v3CertificateBuilder addExtension(ASN1ObjectIdentifier oid, bool isCritical, ASN1Encodable value)
		{
			CertUtils.addExtension(extGenerator, oid, isCritical, value);

			return this;
		}

		/// <summary>
		/// Add a given extension field for the standard extensions tag (tag 3).
		/// </summary>
		/// <param name="extension"> the full extension value. </param>
		/// <returns> this builder object. </returns>
		public virtual X509v3CertificateBuilder addExtension(Extension extension)
		{
			extGenerator.addExtension(extension);

			return this;
		}

		/// <summary>
		/// Add a given extension field for the standard extensions tag (tag 3) using a byte encoding of the
		/// extension value.
		/// </summary>
		/// <param name="oid"> the OID defining the extension type. </param>
		/// <param name="isCritical"> true if the extension is critical, false otherwise. </param>
		/// <param name="encodedValue"> a byte array representing the encoding of the extension value. </param>
		/// <returns> this builder object. </returns>
		public virtual X509v3CertificateBuilder addExtension(ASN1ObjectIdentifier oid, bool isCritical, byte[] encodedValue)
		{
			extGenerator.addExtension(oid, isCritical, encodedValue);

			return this;
		}

		/// <summary>
		/// Add a given extension field for the standard extensions tag (tag 3)
		/// copying the extension value from another certificate.
		/// </summary>
		/// <param name="oid"> the OID defining the extension type. </param>
		/// <param name="isCritical"> true if the copied extension is to be marked as critical, false otherwise. </param>
		/// <param name="certHolder"> the holder for the certificate that the extension is to be copied from. </param>
		/// <returns> this builder object. </returns>
		public virtual X509v3CertificateBuilder copyAndAddExtension(ASN1ObjectIdentifier oid, bool isCritical, X509CertificateHolder certHolder)
		{
			Certificate cert = certHolder.toASN1Structure();

			Extension extension = cert.getTBSCertificate().getExtensions().getExtension(oid);

			if (extension == null)
			{
				throw new NullPointerException("extension " + oid + " not present");
			}

			extGenerator.addExtension(oid, isCritical, extension.getExtnValue().getOctets());

			return this;
		}

		/// <summary>
		/// Generate an X.509 certificate, based on the current issuer and subject
		/// using the passed in signer.
		/// </summary>
		/// <param name="signer"> the content signer to be used to generate the signature validating the certificate. </param>
		/// <returns> a holder containing the resulting signed certificate. </returns>
		public virtual X509CertificateHolder build(ContentSigner signer)
		{
			tbsGen.setSignature(signer.getAlgorithmIdentifier());

			if (!extGenerator.isEmpty())
			{
				tbsGen.setExtensions(extGenerator.generate());
			}

			return CertUtils.generateFullCert(signer, tbsGen.generateTBSCertificate());
		}
	}
}