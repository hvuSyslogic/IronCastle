using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.pkcs
{
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;
	using Attribute = org.bouncycastle.asn1.pkcs.Attribute;
	using CRLBag = org.bouncycastle.asn1.pkcs.CRLBag;
	using CertBag = org.bouncycastle.asn1.pkcs.CertBag;
	using EncryptedPrivateKeyInfo = org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SafeBag = org.bouncycastle.asn1.pkcs.SafeBag;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using CertificateList = org.bouncycastle.asn1.x509.CertificateList;
	using X509CRLHolder = org.bouncycastle.cert.X509CRLHolder;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;

	public class PKCS12SafeBag
	{
		public static readonly ASN1ObjectIdentifier friendlyNameAttribute = PKCSObjectIdentifiers_Fields.pkcs_9_at_friendlyName;
		public static readonly ASN1ObjectIdentifier localKeyIdAttribute = PKCSObjectIdentifiers_Fields.pkcs_9_at_localKeyId;

		private SafeBag safeBag;

		public PKCS12SafeBag(SafeBag safeBag)
		{
			this.safeBag = safeBag;
		}

		/// <summary>
		/// Return the underlying ASN.1 structure for this safe bag.
		/// </summary>
		/// <returns> a SafeBag </returns>
		public virtual SafeBag toASN1Structure()
		{
			return safeBag;
		}

		/// <summary>
		/// Return the BagId giving the type of content in the bag.
		/// </summary>
		/// <returns> the bagId </returns>
		public virtual ASN1ObjectIdentifier getType()
		{
			return safeBag.getBagId();
		}

		public virtual Attribute[] getAttributes()
		{
			ASN1Set attrs = safeBag.getBagAttributes();

			if (attrs == null)
			{
				return null;
			}

			Attribute[] attributes = new Attribute[attrs.size()];
			for (int i = 0; i != attrs.size(); i++)
			{
				attributes[i] = Attribute.getInstance(attrs.getObjectAt(i));
			}

			return attributes;
		}

		public virtual object getBagValue()
		{
			if (getType().Equals(PKCSObjectIdentifiers_Fields.pkcs8ShroudedKeyBag))
			{
				return new PKCS8EncryptedPrivateKeyInfo(EncryptedPrivateKeyInfo.getInstance(safeBag.getBagValue()));
			}
			if (getType().Equals(PKCSObjectIdentifiers_Fields.certBag))
			{
				CertBag certBag = CertBag.getInstance(safeBag.getBagValue());

				return new X509CertificateHolder(Certificate.getInstance(ASN1OctetString.getInstance(certBag.getCertValue()).getOctets()));
			}
			if (getType().Equals(PKCSObjectIdentifiers_Fields.keyBag))
			{
				return PrivateKeyInfo.getInstance(safeBag.getBagValue());
			}
			if (getType().Equals(PKCSObjectIdentifiers_Fields.crlBag))
			{
				CRLBag crlBag = CRLBag.getInstance(safeBag.getBagValue());

				return new X509CRLHolder(CertificateList.getInstance(ASN1OctetString.getInstance(crlBag.getCrlValue()).getOctets()));
			}

			return safeBag.getBagValue();
		}
	}

}