using System;

namespace org.bouncycastle.cert
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1GeneralizedTime = org.bouncycastle.asn1.ASN1GeneralizedTime;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using AttCertIssuer = org.bouncycastle.asn1.x509.AttCertIssuer;
	using Attribute = org.bouncycastle.asn1.x509.Attribute;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using ExtensionsGenerator = org.bouncycastle.asn1.x509.ExtensionsGenerator;
	using V2AttributeCertificateInfoGenerator = org.bouncycastle.asn1.x509.V2AttributeCertificateInfoGenerator;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;

	/// <summary>
	/// class to produce an X.509 Version 2 AttributeCertificate.
	/// </summary>
	public class X509v2AttributeCertificateBuilder
	{
		private V2AttributeCertificateInfoGenerator acInfoGen;
		private ExtensionsGenerator extGenerator;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="holder"> holder certificate details </param>
		/// <param name="issuer"> issuer of this attribute certificate. </param>
		/// <param name="serialNumber"> serial number of this attribute certificate. </param>
		/// <param name="notBefore"> the date before which the certificate is not valid. </param>
		/// <param name="notAfter"> the date after which the certificate is not valid. </param>
		public X509v2AttributeCertificateBuilder(AttributeCertificateHolder holder, AttributeCertificateIssuer issuer, BigInteger serialNumber, DateTime notBefore, DateTime notAfter)
		{
			acInfoGen = new V2AttributeCertificateInfoGenerator();
			extGenerator = new ExtensionsGenerator();

			acInfoGen.setHolder(holder.holder);
			acInfoGen.setIssuer(AttCertIssuer.getInstance(issuer.form));
			acInfoGen.setSerialNumber(new ASN1Integer(serialNumber));
			acInfoGen.setStartDate(new ASN1GeneralizedTime(notBefore));
			acInfoGen.setEndDate(new ASN1GeneralizedTime(notAfter));
		}

		/// <summary>
		/// Base constructor with locale for interpreting dates. You may need to use this constructor if the default locale
		/// doesn't use a Gregorian calender so that the GeneralizedTime produced is compatible with other ASN.1 implementations.
		/// </summary>
		/// <param name="holder"> holder certificate details </param>
		/// <param name="issuer"> issuer of this attribute certificate. </param>
		/// <param name="serialNumber"> serial number of this attribute certificate. </param>
		/// <param name="notBefore"> the date before which the certificate is not valid. </param>
		/// <param name="notAfter"> the date after which the certificate is not valid. </param>
		/// <param name="dateLocale"> locale to be used for date interpretation. </param>
		public X509v2AttributeCertificateBuilder(AttributeCertificateHolder holder, AttributeCertificateIssuer issuer, BigInteger serialNumber, DateTime notBefore, DateTime notAfter, Locale dateLocale)
		{
			acInfoGen = new V2AttributeCertificateInfoGenerator();
			extGenerator = new ExtensionsGenerator();

			acInfoGen.setHolder(holder.holder);
			acInfoGen.setIssuer(AttCertIssuer.getInstance(issuer.form));
			acInfoGen.setSerialNumber(new ASN1Integer(serialNumber));
			acInfoGen.setStartDate(new ASN1GeneralizedTime(notBefore, dateLocale));
			acInfoGen.setEndDate(new ASN1GeneralizedTime(notAfter, dateLocale));
		}

		/// <summary>
		/// Add an attribute to the certification request we are building.
		/// </summary>
		/// <param name="attrType"> the OID giving the type of the attribute. </param>
		/// <param name="attrValue"> the ASN.1 structure that forms the value of the attribute. </param>
		/// <returns> this builder object. </returns>
		public virtual X509v2AttributeCertificateBuilder addAttribute(ASN1ObjectIdentifier attrType, ASN1Encodable attrValue)
		{
			acInfoGen.addAttribute(new Attribute(attrType, new DERSet(attrValue)));

			return this;
		}

		/// <summary>
		/// Add an attribute with multiple values to the certification request we are building.
		/// </summary>
		/// <param name="attrType"> the OID giving the type of the attribute. </param>
		/// <param name="attrValues"> an array of ASN.1 structures that form the value of the attribute. </param>
		/// <returns> this builder object. </returns>
		public virtual X509v2AttributeCertificateBuilder addAttribute(ASN1ObjectIdentifier attrType, ASN1Encodable[] attrValues)
		{
			acInfoGen.addAttribute(new Attribute(attrType, new DERSet(attrValues)));

			return this;
		}

		public virtual void setIssuerUniqueId(bool[] iui)
		{
			acInfoGen.setIssuerUniqueID(CertUtils.booleanToBitString(iui));
		}

		/// <summary>
		/// Add a given extension field for the standard extensions tag made up of the passed in parameters.
		/// </summary>
		/// <param name="oid"> the OID defining the extension type. </param>
		/// <param name="isCritical"> true if the extension is critical, false otherwise. </param>
		/// <param name="value"> the ASN.1 structure that forms the extension's value. </param>
		/// <returns> this builder object. </returns>
		public virtual X509v2AttributeCertificateBuilder addExtension(ASN1ObjectIdentifier oid, bool isCritical, ASN1Encodable value)
		{
			CertUtils.addExtension(extGenerator, oid, isCritical, value);

			return this;
		}

		/// <summary>
		/// Add a given extension field for the standard extensions using a byte encoding of the
		/// extension value.
		/// </summary>
		/// <param name="oid"> the OID defining the extension type. </param>
		/// <param name="isCritical"> true if the extension is critical, false otherwise. </param>
		/// <param name="encodedValue"> a byte array representing the encoding of the extension value. </param>
		/// <returns> this builder object. </returns>
		public virtual X509v2AttributeCertificateBuilder addExtension(ASN1ObjectIdentifier oid, bool isCritical, byte[] encodedValue)
		{
			extGenerator.addExtension(oid, isCritical, encodedValue);

			return this;
		}

		/// <summary>
		/// Add a given extension field for the standard extensions.
		/// </summary>
		/// <param name="extension"> the full extension value. </param>
		/// <returns> this builder object. </returns>
		public virtual X509v2AttributeCertificateBuilder addExtension(Extension extension)
		{
			extGenerator.addExtension(extension);

			return this;
		}

	   /// <summary>
	   /// Generate an X509 certificate, based on the current issuer and subject
	   /// using the passed in signer.
	   /// </summary>
	   /// <param name="signer"> the content signer to be used to generate the signature validating the certificate. </param>
	   /// <returns> a holder containing the resulting signed certificate. </returns>
		public virtual X509AttributeCertificateHolder build(ContentSigner signer)
		{
			acInfoGen.setSignature(signer.getAlgorithmIdentifier());

			if (!extGenerator.isEmpty())
			{
				acInfoGen.setExtensions(extGenerator.generate());
			}

			return CertUtils.generateFullAttrCert(signer, acInfoGen.generateAttributeCertificateInfo());
		}
	}

}