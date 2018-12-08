using org.bouncycastle.bcpg;
using org.bouncycastle.asn1.nist;

namespace org.bouncycastle.openpgp.@operator
{

	using ASN1Object = org.bouncycastle.asn1.ASN1Object;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using ECDHPublicBCPGKey = org.bouncycastle.bcpg.ECDHPublicBCPGKey;
	using HashAlgorithmTags = org.bouncycastle.bcpg.HashAlgorithmTags;
	using PublicKeyAlgorithmTags = org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
	using PublicKeyPacket = org.bouncycastle.bcpg.PublicKeyPacket;
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;
	using Hex = org.bouncycastle.util.encoders.Hex;


	public class RFC6637Utils
	{
		private RFC6637Utils()
		{

		}

		// "Anonymous Sender    ", which is the octet sequence
		private static readonly byte[] ANONYMOUS_SENDER = Hex.decode("416E6F6E796D6F75732053656E64657220202020");

		public static string getAgreementAlgorithm(PublicKeyPacket pubKeyData)
		{
			ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey)pubKeyData.getKey();

			switch (ecKey.getHashAlgorithm())
			{
			case HashAlgorithmTags_Fields.SHA256:
				return "ECCDHwithSHA256CKDF";
			case HashAlgorithmTags_Fields.SHA384:
				return "ECCDHwithSHA384CKDF";
			case HashAlgorithmTags_Fields.SHA512:
				return "ECCDHwithSHA512CKDF";
			default:
				throw new IllegalArgumentException("Unknown hash algorithm specified: " + ecKey.getHashAlgorithm());
			}
		}


		public static ASN1ObjectIdentifier getKeyEncryptionOID(int algID)
		{
			switch (algID)
			{
			case SymmetricKeyAlgorithmTags_Fields.AES_128:
				return NISTObjectIdentifiers_Fields.id_aes128_wrap;
			case SymmetricKeyAlgorithmTags_Fields.AES_192:
				return NISTObjectIdentifiers_Fields.id_aes192_wrap;
			case SymmetricKeyAlgorithmTags_Fields.AES_256:
				return NISTObjectIdentifiers_Fields.id_aes256_wrap;
			default:
				throw new PGPException("unknown symmetric algorithm ID: " + algID);
			}
		}

		// RFC 6637 - Section 8
		// curve_OID_len = (byte)len(curve_OID);
		// Param = curve_OID_len || curve_OID || public_key_alg_ID || 03
		// || 01 || KDF_hash_ID || KEK_alg_ID for AESKeyWrap || "Anonymous
		// Sender    " || recipient_fingerprint;
		// Z_len = the key size for the KEK_alg_ID used with AESKeyWrap
		// Compute Z = KDF( S, Z_len, Param );
		public static byte[] createUserKeyingMaterial(PublicKeyPacket pubKeyData, KeyFingerPrintCalculator fingerPrintCalculator)
		{
			ByteArrayOutputStream pOut = new ByteArrayOutputStream();
			ECDHPublicBCPGKey ecKey = (ECDHPublicBCPGKey)pubKeyData.getKey();
			byte[] encOid = ecKey.getCurveOID().getEncoded();

			pOut.write(encOid, 1, encOid.Length - 1);
			pOut.write(pubKeyData.getAlgorithm());
			pOut.write(0x03);
			pOut.write(0x01);
			pOut.write(ecKey.getHashAlgorithm());
			pOut.write(ecKey.getSymmetricKeyAlgorithm());
			pOut.write(ANONYMOUS_SENDER);
			pOut.write(fingerPrintCalculator.calculateFingerprint(pubKeyData));

			return pOut.toByteArray();
		}
	}

}