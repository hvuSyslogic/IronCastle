namespace org.bouncycastle.cms
{

	using KEKIdentifier = org.bouncycastle.asn1.cms.KEKIdentifier;
	using KEKRecipientInfo = org.bouncycastle.asn1.cms.KEKRecipientInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// the RecipientInfo class for a recipient who has been sent a message
	/// encrypted using a secret key known to the other side.
	/// </summary>
	public class KEKRecipientInformation : RecipientInformation
	{
		private KEKRecipientInfo info;

		public KEKRecipientInformation(KEKRecipientInfo info, AlgorithmIdentifier messageAlgorithm, CMSSecureReadable secureReadable, AuthAttributesProvider additionalData) : base(info.getKeyEncryptionAlgorithm(), messageAlgorithm, secureReadable, additionalData)
		{

			this.info = info;

			KEKIdentifier kekId = info.getKekid();

			this.rid = new KEKRecipientId(kekId.getKeyIdentifier().getOctets());
		}

		public override RecipientOperator getRecipientOperator(Recipient recipient)
		{
			return ((KEKRecipient)recipient).getRecipientOperator(keyEncAlg, messageAlgorithm, info.getEncryptedKey().getOctets());
		}
	}

}