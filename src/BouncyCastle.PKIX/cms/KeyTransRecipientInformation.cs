namespace org.bouncycastle.cms
{
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using KeyTransRecipientInfo = org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
	using RecipientIdentifier = org.bouncycastle.asn1.cms.RecipientIdentifier;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// the KeyTransRecipientInformation class for a recipient who has been sent a secret
	/// key encrypted using their public key that needs to be used to
	/// extract the message.
	/// </summary>
	public class KeyTransRecipientInformation : RecipientInformation
	{
		private KeyTransRecipientInfo info;

		public KeyTransRecipientInformation(KeyTransRecipientInfo info, AlgorithmIdentifier messageAlgorithm, CMSSecureReadable secureReadable, AuthAttributesProvider additionalData) : base(info.getKeyEncryptionAlgorithm(), messageAlgorithm, secureReadable, additionalData)
		{

			this.info = info;

			RecipientIdentifier r = info.getRecipientIdentifier();

			if (r.isTagged())
			{
				ASN1OctetString octs = ASN1OctetString.getInstance(r.getId());

				rid = new KeyTransRecipientId(octs.getOctets());
			}
			else
			{
				IssuerAndSerialNumber iAnds = IssuerAndSerialNumber.getInstance(r.getId());

				rid = new KeyTransRecipientId(iAnds.getName(), iAnds.getSerialNumber().getValue());
			}
		}

		public override RecipientOperator getRecipientOperator(Recipient recipient)
		{
			return ((KeyTransRecipient)recipient).getRecipientOperator(keyEncAlg, messageAlgorithm, info.getEncryptedKey().getOctets());
		}
	}

}