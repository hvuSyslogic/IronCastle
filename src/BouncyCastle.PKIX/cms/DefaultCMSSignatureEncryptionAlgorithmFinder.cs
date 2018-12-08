using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.teletrust;

namespace org.bouncycastle.cms
{

	using DERNull = org.bouncycastle.asn1.DERNull;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public class DefaultCMSSignatureEncryptionAlgorithmFinder : CMSSignatureEncryptionAlgorithmFinder
	{
		private static readonly Set RSA_PKCS1d5 = new HashSet();

		static DefaultCMSSignatureEncryptionAlgorithmFinder()
		{
			RSA_PKCS1d5.add(PKCSObjectIdentifiers_Fields.md2WithRSAEncryption);
			RSA_PKCS1d5.add(PKCSObjectIdentifiers_Fields.md4WithRSAEncryption);
			RSA_PKCS1d5.add(PKCSObjectIdentifiers_Fields.md5WithRSAEncryption);
			RSA_PKCS1d5.add(PKCSObjectIdentifiers_Fields.sha1WithRSAEncryption);
			RSA_PKCS1d5.add(OIWObjectIdentifiers_Fields.md4WithRSAEncryption);
			RSA_PKCS1d5.add(OIWObjectIdentifiers_Fields.md4WithRSA);
			RSA_PKCS1d5.add(OIWObjectIdentifiers_Fields.md5WithRSA);
			RSA_PKCS1d5.add(OIWObjectIdentifiers_Fields.sha1WithRSA);
			RSA_PKCS1d5.add(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd128);
			RSA_PKCS1d5.add(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd160);
			RSA_PKCS1d5.add(TeleTrusTObjectIdentifiers_Fields.rsaSignatureWithripemd256);
		}

		public virtual AlgorithmIdentifier findEncryptionAlgorithm(AlgorithmIdentifier signatureAlgorithm)
		{
				   // RFC3370 section 3.2 with RFC 5754 update
			if (RSA_PKCS1d5.contains(signatureAlgorithm.getAlgorithm()))
			{
				return new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.rsaEncryption, DERNull.INSTANCE);
			}

			return signatureAlgorithm;
		}
	}

}