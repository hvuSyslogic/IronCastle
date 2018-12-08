using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.cms
{
	using DERNull = org.bouncycastle.asn1.DERNull;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	public interface PasswordRecipient : Recipient
	{

		byte[] calculateDerivedKey(int schemeID, AlgorithmIdentifier derivationAlgorithm, int keySize);

		RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, byte[] derivedKey, byte[] encryptedEncryptedContentKey);

		int getPasswordConversionScheme();

		char[] getPassword();
	}

	public static class PasswordRecipient_Fields
	{
		public const int PKCS5_SCHEME2 = 0;
		public const int PKCS5_SCHEME2_UTF8 = 1;
	}

	public sealed class PasswordRecipient_PRF
	{
		public static readonly PasswordRecipient_PRF HMacSHA1 = new PasswordRecipient_PRF("HMacSHA1", new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA1, DERNull.INSTANCE));
		public static readonly PasswordRecipient_PRF HMacSHA224 = new PasswordRecipient_PRF("HMacSHA224", new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA224, DERNull.INSTANCE));
		public static readonly PasswordRecipient_PRF HMacSHA256 = new PasswordRecipient_PRF("HMacSHA256", new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA256, DERNull.INSTANCE));
		public static readonly PasswordRecipient_PRF HMacSHA384 = new PasswordRecipient_PRF("HMacSHA384", new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA384, DERNull.INSTANCE));
		public static readonly PasswordRecipient_PRF HMacSHA512 = new PasswordRecipient_PRF("HMacSHA512", new AlgorithmIdentifier(PKCSObjectIdentifiers_Fields.id_hmacWithSHA512, DERNull.INSTANCE));

		internal readonly string hmac;
		internal readonly AlgorithmIdentifier prfAlgID;

		public PasswordRecipient_PRF(string hmac, AlgorithmIdentifier prfAlgID)
		{
			this.hmac = hmac;
			this.prfAlgID = prfAlgID;
		}

		public string getName()
		{
			return hmac;
		}

		public AlgorithmIdentifier getAlgorithmID()
		{
			return prfAlgID;
		}
	}

}