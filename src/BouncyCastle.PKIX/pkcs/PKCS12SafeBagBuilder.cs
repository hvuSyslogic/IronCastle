using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.pkcs
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSet = org.bouncycastle.asn1.DERSet;
	using Attribute = org.bouncycastle.asn1.pkcs.Attribute;
	using CertBag = org.bouncycastle.asn1.pkcs.CertBag;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SafeBag = org.bouncycastle.asn1.pkcs.SafeBag;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using CertificateList = org.bouncycastle.asn1.x509.CertificateList;
	using X509CRLHolder = org.bouncycastle.cert.X509CRLHolder;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;

	public class PKCS12SafeBagBuilder
	{
		private ASN1ObjectIdentifier bagType;
		private ASN1Encodable bagValue;
		private ASN1EncodableVector bagAttrs = new ASN1EncodableVector();

		public PKCS12SafeBagBuilder(PrivateKeyInfo privateKeyInfo, OutputEncryptor encryptor)
		{
			this.bagType = PKCSObjectIdentifiers_Fields.pkcs8ShroudedKeyBag;
			this.bagValue = (new PKCS8EncryptedPrivateKeyInfoBuilder(privateKeyInfo)).build(encryptor).toASN1Structure();
		}

		public PKCS12SafeBagBuilder(PrivateKeyInfo privateKeyInfo)
		{
			this.bagType = PKCSObjectIdentifiers_Fields.keyBag;
			this.bagValue = privateKeyInfo;
		}

		public PKCS12SafeBagBuilder(X509CertificateHolder certificate) : this(certificate.toASN1Structure())
		{
		}

		public PKCS12SafeBagBuilder(X509CRLHolder crl) : this(crl.toASN1Structure())
		{
		}

		public PKCS12SafeBagBuilder(Certificate certificate)
		{
			this.bagType = PKCSObjectIdentifiers_Fields.certBag;
			this.bagValue = new CertBag(PKCSObjectIdentifiers_Fields.x509Certificate, new DEROctetString(certificate.getEncoded()));
		}

		public PKCS12SafeBagBuilder(CertificateList crl)
		{
			this.bagType = PKCSObjectIdentifiers_Fields.crlBag;
			this.bagValue = new CertBag(PKCSObjectIdentifiers_Fields.x509Crl, new DEROctetString(crl.getEncoded()));
		}

		public virtual PKCS12SafeBagBuilder addBagAttribute(ASN1ObjectIdentifier attrType, ASN1Encodable attrValue)
		{
			bagAttrs.add(new Attribute(attrType, new DERSet(attrValue)));

			return this;
		}

		public virtual PKCS12SafeBag build()
		{
			return new PKCS12SafeBag(new SafeBag(bagType, bagValue, new DERSet(bagAttrs)));
		}
	}

}