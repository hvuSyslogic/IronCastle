namespace org.bouncycastle.cms
{
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using KeyTransRecipientInfo = org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
	using RecipientIdentifier = org.bouncycastle.asn1.cms.RecipientIdentifier;
	using RecipientInfo = org.bouncycastle.asn1.cms.RecipientInfo;
	using AsymmetricKeyWrapper = org.bouncycastle.@operator.AsymmetricKeyWrapper;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using OperatorException = org.bouncycastle.@operator.OperatorException;

	public abstract class KeyTransRecipientInfoGenerator : RecipientInfoGenerator
	{
		protected internal readonly AsymmetricKeyWrapper wrapper;

		private IssuerAndSerialNumber issuerAndSerial;
		private byte[] subjectKeyIdentifier;

		public KeyTransRecipientInfoGenerator(IssuerAndSerialNumber issuerAndSerial, AsymmetricKeyWrapper wrapper)
		{
			this.issuerAndSerial = issuerAndSerial;
			this.wrapper = wrapper;
		}

		public KeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, AsymmetricKeyWrapper wrapper)
		{
			this.subjectKeyIdentifier = subjectKeyIdentifier;
			this.wrapper = wrapper;
		}

		public RecipientInfo generate(GenericKey contentEncryptionKey)
		{
			byte[] encryptedKeyBytes;
			try
			{
				encryptedKeyBytes = wrapper.generateWrappedKey(contentEncryptionKey);
			}
			catch (OperatorException e)
			{
				throw new CMSException("exception wrapping content key: " + e.Message, e);
			}

			RecipientIdentifier recipId;
			if (issuerAndSerial != null)
			{
				recipId = new RecipientIdentifier(issuerAndSerial);
			}
			else
			{
				recipId = new RecipientIdentifier(new DEROctetString(subjectKeyIdentifier));
			}

			return new RecipientInfo(new KeyTransRecipientInfo(recipId, wrapper.getAlgorithmIdentifier(), new DEROctetString(encryptedKeyBytes)));
		}
	}
}