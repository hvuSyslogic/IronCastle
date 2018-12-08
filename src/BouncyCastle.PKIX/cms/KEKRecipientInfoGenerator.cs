namespace org.bouncycastle.cms
{
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using KEKIdentifier = org.bouncycastle.asn1.cms.KEKIdentifier;
	using KEKRecipientInfo = org.bouncycastle.asn1.cms.KEKRecipientInfo;
	using RecipientInfo = org.bouncycastle.asn1.cms.RecipientInfo;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using OperatorException = org.bouncycastle.@operator.OperatorException;
	using SymmetricKeyWrapper = org.bouncycastle.@operator.SymmetricKeyWrapper;

	public abstract class KEKRecipientInfoGenerator : RecipientInfoGenerator
	{
		private readonly KEKIdentifier kekIdentifier;

		protected internal readonly SymmetricKeyWrapper wrapper;

		public KEKRecipientInfoGenerator(KEKIdentifier kekIdentifier, SymmetricKeyWrapper wrapper)
		{
			this.kekIdentifier = kekIdentifier;
			this.wrapper = wrapper;
		}

		public RecipientInfo generate(GenericKey contentEncryptionKey)
		{
			try
			{
				ASN1OctetString encryptedKey = new DEROctetString(wrapper.generateWrappedKey(contentEncryptionKey));

				return new RecipientInfo(new KEKRecipientInfo(kekIdentifier, wrapper.getAlgorithmIdentifier(), encryptedKey));
			}
			catch (OperatorException e)
			{
				throw new CMSException("exception wrapping content key: " + e.Message, e);
			}
		}
	}
}