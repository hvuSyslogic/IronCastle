using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.cryptopro;

namespace org.bouncycastle.cms
{
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using KeyAgreeRecipientInfo = org.bouncycastle.asn1.cms.KeyAgreeRecipientInfo;
	using OriginatorIdentifierOrKey = org.bouncycastle.asn1.cms.OriginatorIdentifierOrKey;
	using OriginatorPublicKey = org.bouncycastle.asn1.cms.OriginatorPublicKey;
	using RecipientInfo = org.bouncycastle.asn1.cms.RecipientInfo;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using Gost2814789KeyWrapParameters = org.bouncycastle.asn1.cryptopro.Gost2814789KeyWrapParameters;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using GenericKey = org.bouncycastle.@operator.GenericKey;

	public abstract class KeyAgreeRecipientInfoGenerator : RecipientInfoGenerator
	{
		private ASN1ObjectIdentifier keyAgreementOID;
		private ASN1ObjectIdentifier keyEncryptionOID;
		private SubjectPublicKeyInfo originatorKeyInfo;

		public KeyAgreeRecipientInfoGenerator(ASN1ObjectIdentifier keyAgreementOID, SubjectPublicKeyInfo originatorKeyInfo, ASN1ObjectIdentifier keyEncryptionOID)
		{
			this.originatorKeyInfo = originatorKeyInfo;
			this.keyAgreementOID = keyAgreementOID;
			this.keyEncryptionOID = keyEncryptionOID;
		}

		public virtual RecipientInfo generate(GenericKey contentEncryptionKey)
		{
			OriginatorIdentifierOrKey originator = new OriginatorIdentifierOrKey(createOriginatorPublicKey(originatorKeyInfo));

			AlgorithmIdentifier keyEncAlg;
			if (CMSUtils.isDES(keyEncryptionOID.getId()) || keyEncryptionOID.Equals(PKCSObjectIdentifiers_Fields.id_alg_CMSRC2wrap))
			{
				keyEncAlg = new AlgorithmIdentifier(keyEncryptionOID, DERNull.INSTANCE);
			}
			else if (CMSUtils.isGOST(keyAgreementOID))
			{
				keyEncAlg = new AlgorithmIdentifier(keyEncryptionOID, new Gost2814789KeyWrapParameters(CryptoProObjectIdentifiers_Fields.id_Gost28147_89_CryptoPro_A_ParamSet));
			}
			else
			{
				keyEncAlg = new AlgorithmIdentifier(keyEncryptionOID);
			}

			AlgorithmIdentifier keyAgreeAlg = new AlgorithmIdentifier(keyAgreementOID, keyEncAlg);

			ASN1Sequence recipients = generateRecipientEncryptedKeys(keyAgreeAlg, keyEncAlg, contentEncryptionKey);
			byte[] userKeyingMaterial = getUserKeyingMaterial(keyAgreeAlg);

			if (userKeyingMaterial != null)
			{
				return new RecipientInfo(new KeyAgreeRecipientInfo(originator, new DEROctetString(userKeyingMaterial), keyAgreeAlg, recipients));
			}
			else
			{
				return new RecipientInfo(new KeyAgreeRecipientInfo(originator, null, keyAgreeAlg, recipients));
			}
		}

		public virtual OriginatorPublicKey createOriginatorPublicKey(SubjectPublicKeyInfo originatorKeyInfo)
		{
			return new OriginatorPublicKey(new AlgorithmIdentifier(originatorKeyInfo.getAlgorithm().getAlgorithm(), DERNull.INSTANCE), originatorKeyInfo.getPublicKeyData().getBytes());
		}

		public abstract ASN1Sequence generateRecipientEncryptedKeys(AlgorithmIdentifier keyAgreeAlgorithm, AlgorithmIdentifier keyEncAlgorithm, GenericKey contentEncryptionKey);

		public abstract byte[] getUserKeyingMaterial(AlgorithmIdentifier keyAgreeAlgorithm);

	}
}