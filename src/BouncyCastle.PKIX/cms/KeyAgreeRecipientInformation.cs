namespace org.bouncycastle.cms
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using KeyAgreeRecipientIdentifier = org.bouncycastle.asn1.cms.KeyAgreeRecipientIdentifier;
	using KeyAgreeRecipientInfo = org.bouncycastle.asn1.cms.KeyAgreeRecipientInfo;
	using OriginatorIdentifierOrKey = org.bouncycastle.asn1.cms.OriginatorIdentifierOrKey;
	using OriginatorPublicKey = org.bouncycastle.asn1.cms.OriginatorPublicKey;
	using RecipientEncryptedKey = org.bouncycastle.asn1.cms.RecipientEncryptedKey;
	using RecipientKeyIdentifier = org.bouncycastle.asn1.cms.RecipientKeyIdentifier;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectKeyIdentifier = org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

	/// <summary>
	/// the RecipientInfo class for a recipient who has been sent a message
	/// encrypted using key agreement.
	/// </summary>
	public class KeyAgreeRecipientInformation : RecipientInformation
	{
		private KeyAgreeRecipientInfo info;
		private ASN1OctetString encryptedKey;

		internal static void readRecipientInfo(List infos, KeyAgreeRecipientInfo info, AlgorithmIdentifier messageAlgorithm, CMSSecureReadable secureReadable, AuthAttributesProvider additionalData)
		{
			ASN1Sequence s = info.getRecipientEncryptedKeys();

			for (int i = 0; i < s.size(); ++i)
			{
				RecipientEncryptedKey id = RecipientEncryptedKey.getInstance(s.getObjectAt(i));

				RecipientId rid;

				KeyAgreeRecipientIdentifier karid = id.getIdentifier();
				IssuerAndSerialNumber iAndSN = karid.getIssuerAndSerialNumber();

				if (iAndSN != null)
				{
					rid = new KeyAgreeRecipientId(iAndSN.getName(), iAndSN.getSerialNumber().getValue());
				}
				else
				{
					RecipientKeyIdentifier rKeyID = karid.getRKeyID();

					// Note: 'date' and 'other' fields of RecipientKeyIdentifier appear to be only informational

					rid = new KeyAgreeRecipientId(rKeyID.getSubjectKeyIdentifier().getOctets());
				}

				infos.add(new KeyAgreeRecipientInformation(info, rid, id.getEncryptedKey(), messageAlgorithm, secureReadable, additionalData));
			}
		}

		public KeyAgreeRecipientInformation(KeyAgreeRecipientInfo info, RecipientId rid, ASN1OctetString encryptedKey, AlgorithmIdentifier messageAlgorithm, CMSSecureReadable secureReadable, AuthAttributesProvider additionalData) : base(info.getKeyEncryptionAlgorithm(), messageAlgorithm, secureReadable, additionalData)
		{

			this.info = info;
			this.rid = rid;
			this.encryptedKey = encryptedKey;
		}

		private SubjectPublicKeyInfo getSenderPublicKeyInfo(AlgorithmIdentifier recKeyAlgId, OriginatorIdentifierOrKey originator)
		{
			OriginatorPublicKey opk = originator.getOriginatorKey();
			if (opk != null)
			{
				return getPublicKeyInfoFromOriginatorPublicKey(recKeyAlgId, opk);
			}

			OriginatorId origID;

			IssuerAndSerialNumber iAndSN = originator.getIssuerAndSerialNumber();
			if (iAndSN != null)
			{
				origID = new OriginatorId(iAndSN.getName(), iAndSN.getSerialNumber().getValue());
			}
			else
			{
				SubjectKeyIdentifier ski = originator.getSubjectKeyIdentifier();

				origID = new OriginatorId(ski.getKeyIdentifier());
			}

			return getPublicKeyInfoFromOriginatorId(origID);
		}

		private SubjectPublicKeyInfo getPublicKeyInfoFromOriginatorPublicKey(AlgorithmIdentifier recKeyAlgId, OriginatorPublicKey originatorPublicKey)
		{
			SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(recKeyAlgId, originatorPublicKey.getPublicKey().getBytes());

			return pubInfo;
		}

		private SubjectPublicKeyInfo getPublicKeyInfoFromOriginatorId(OriginatorId origID)
		{
			// TODO Support all alternatives for OriginatorIdentifierOrKey
			// see RFC 3852 6.2.2
			throw new CMSException("No support for 'originator' as IssuerAndSerialNumber or SubjectKeyIdentifier");
		}

		public override RecipientOperator getRecipientOperator(Recipient recipient)
		{
			KeyAgreeRecipient agreeRecipient = (KeyAgreeRecipient)recipient;
					AlgorithmIdentifier recKeyAlgId = agreeRecipient.getPrivateKeyAlgorithmIdentifier();

			return ((KeyAgreeRecipient)recipient).getRecipientOperator(keyEncAlg, messageAlgorithm, getSenderPublicKeyInfo(recKeyAlgId, info.getOriginator()), info.getUserKeyingMaterial(), encryptedKey.getOctets());
		}
	}

}