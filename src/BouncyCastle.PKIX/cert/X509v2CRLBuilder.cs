using System;

namespace org.bouncycastle.cert
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1GeneralizedTime = org.bouncycastle.asn1.ASN1GeneralizedTime;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using ExtensionsGenerator = org.bouncycastle.asn1.x509.ExtensionsGenerator;
	using TBSCertList = org.bouncycastle.asn1.x509.TBSCertList;
	using Time = org.bouncycastle.asn1.x509.Time;
	using V2TBSCertListGenerator = org.bouncycastle.asn1.x509.V2TBSCertListGenerator;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;

	/// <summary>
	/// class to produce an X.509 Version 2 CRL.
	/// </summary>
	public class X509v2CRLBuilder
	{
		private V2TBSCertListGenerator tbsGen;
		private ExtensionsGenerator extGenerator;

		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="issuer"> the issuer this CRL is associated with. </param>
		/// <param name="thisUpdate">  the date of this update. </param>
		public X509v2CRLBuilder(X500Name issuer, DateTime thisUpdate)
		{
			tbsGen = new V2TBSCertListGenerator();
			extGenerator = new ExtensionsGenerator();

			tbsGen.setIssuer(issuer);
			tbsGen.setThisUpdate(new Time(thisUpdate));
		}

		/// <summary>
		/// Basic constructor with Locale. You may need to use this constructor if the default locale
		/// doesn't use a Gregorian calender so that the Time produced is compatible with other ASN.1 implementations.
		/// </summary>
		/// <param name="issuer"> the issuer this CRL is associated with. </param>
		/// <param name="thisUpdate">  the date of this update. </param>
		/// <param name="dateLocale"> locale to be used for date interpretation. </param>
		public X509v2CRLBuilder(X500Name issuer, DateTime thisUpdate, Locale dateLocale)
		{
			tbsGen = new V2TBSCertListGenerator();
			extGenerator = new ExtensionsGenerator();

			tbsGen.setIssuer(issuer);
			tbsGen.setThisUpdate(new Time(thisUpdate, dateLocale));
		}

		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="issuer"> the issuer this CRL is associated with. </param>
		/// <param name="thisUpdate">  the Time of this update. </param>
		public X509v2CRLBuilder(X500Name issuer, Time thisUpdate)
		{
			tbsGen = new V2TBSCertListGenerator();
			extGenerator = new ExtensionsGenerator();

			tbsGen.setIssuer(issuer);
			tbsGen.setThisUpdate(thisUpdate);
		}

		/// <summary>
		/// Set the date by which the next CRL will become available.
		/// </summary>
		/// <param name="date">  date of next CRL update. </param>
		/// <returns> the current builder. </returns>
		public virtual X509v2CRLBuilder setNextUpdate(DateTime date)
		{
			return this.setNextUpdate(new Time(date));
		}

		/// <summary>
		/// Set the date by which the next CRL will become available.
		/// </summary>
		/// <param name="date">  date of next CRL update. </param>
		/// <param name="dateLocale"> locale to be used for date interpretation. </param>
		/// <returns> the current builder. </returns>
		public virtual X509v2CRLBuilder setNextUpdate(DateTime date, Locale dateLocale)
		{
			return this.setNextUpdate(new Time(date, dateLocale));
		}

		/// <summary>
		/// Set the date by which the next CRL will become available.
		/// </summary>
		/// <param name="date">  date of next CRL update. </param>
		/// <returns> the current builder. </returns>
		public virtual X509v2CRLBuilder setNextUpdate(Time date)
		{
			tbsGen.setNextUpdate(date);

			return this;
		}

		/// <summary>
		/// Add a CRL entry with the just reasonCode extension.
		/// </summary>
		/// <param name="userCertificateSerial"> serial number of revoked certificate. </param>
		/// <param name="revocationDate"> date of certificate revocation. </param>
		/// <param name="reason"> the reason code, as indicated in CRLReason, i.e CRLReason.keyCompromise, or 0 if not to be used. </param>
		/// <returns> the current builder. </returns>
		public virtual X509v2CRLBuilder addCRLEntry(BigInteger userCertificateSerial, DateTime revocationDate, int reason)
		{
			tbsGen.addCRLEntry(new ASN1Integer(userCertificateSerial), new Time(revocationDate), reason);

			return this;
		}

		/// <summary>
		/// Add a CRL entry with an invalidityDate extension as well as a reasonCode extension. This is used
		/// where the date of revocation might be after issues with the certificate may have occurred.
		/// </summary>
		/// <param name="userCertificateSerial"> serial number of revoked certificate. </param>
		/// <param name="revocationDate"> date of certificate revocation. </param>
		/// <param name="reason"> the reason code, as indicated in CRLReason, i.e CRLReason.keyCompromise, or 0 if not to be used. </param>
		/// <param name="invalidityDate"> the date on which the private key for the certificate became compromised or the certificate otherwise became invalid. </param>
		/// <returns> the current builder. </returns>
		public virtual X509v2CRLBuilder addCRLEntry(BigInteger userCertificateSerial, DateTime revocationDate, int reason, DateTime invalidityDate)
		{
			tbsGen.addCRLEntry(new ASN1Integer(userCertificateSerial), new Time(revocationDate), reason, new ASN1GeneralizedTime(invalidityDate));

			return this;
		}

		/// <summary>
		/// Add a CRL entry with extensions.
		/// </summary>
		/// <param name="userCertificateSerial"> serial number of revoked certificate. </param>
		/// <param name="revocationDate"> date of certificate revocation. </param>
		/// <param name="extensions"> extension set to be associated with this CRLEntry. </param>
		/// <returns> the current builder. </returns>
		public virtual X509v2CRLBuilder addCRLEntry(BigInteger userCertificateSerial, DateTime revocationDate, Extensions extensions)
		{
			tbsGen.addCRLEntry(new ASN1Integer(userCertificateSerial), new Time(revocationDate), extensions);

			return this;
		}

		/// <summary>
		/// Add the CRLEntry objects contained in a previous CRL.
		/// </summary>
		/// <param name="other"> the X509CRLHolder to source the other entries from. </param>
		/// <returns> the current builder. </returns>
		public virtual X509v2CRLBuilder addCRL(X509CRLHolder other)
		{
			TBSCertList revocations = other.toASN1Structure().getTBSCertList();

			if (revocations != null)
			{
				for (Enumeration en = revocations.getRevokedCertificateEnumeration(); en.hasMoreElements();)
				{
					tbsGen.addCRLEntry(ASN1Sequence.getInstance(((ASN1Encodable)en.nextElement()).toASN1Primitive()));
				}
			}

			return this;
		}

		/// <summary>
		/// Add a given extension field for the standard extensions tag (tag 3)
		/// </summary>
		/// <param name="oid"> the OID defining the extension type. </param>
		/// <param name="isCritical"> true if the extension is critical, false otherwise. </param>
		/// <param name="value"> the ASN.1 structure that forms the extension's value. </param>
		/// <returns> this builder object. </returns>
		public virtual X509v2CRLBuilder addExtension(ASN1ObjectIdentifier oid, bool isCritical, ASN1Encodable value)
		{
			CertUtils.addExtension(extGenerator, oid, isCritical, value);

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
		public virtual X509v2CRLBuilder addExtension(ASN1ObjectIdentifier oid, bool isCritical, byte[] encodedValue)
		{
			extGenerator.addExtension(oid, isCritical, encodedValue);

			return this;
		}

		/// <summary>
		/// Add a given extension field for the standard extensions tag (tag 3).
		/// </summary>
		/// <param name="extension"> the full extension value. </param>
		/// <returns> this builder object. </returns>
		public virtual X509v2CRLBuilder addExtension(Extension extension)
		{
			extGenerator.addExtension(extension);

			return this;
		}

		/// <summary>
		/// Generate an X.509 CRL, based on the current issuer and subject
		/// using the passed in signer.
		/// </summary>
		/// <param name="signer"> the content signer to be used to generate the signature validating the certificate. </param>
		/// <returns> a holder containing the resulting signed certificate. </returns>
		public virtual X509CRLHolder build(ContentSigner signer)
		{
			tbsGen.setSignature(signer.getAlgorithmIdentifier());

			if (!extGenerator.isEmpty())
			{
				tbsGen.setExtensions(extGenerator.generate());
			}

			return CertUtils.generateFullCRL(signer, tbsGen.generateTBSCertList());
		}
	}

}