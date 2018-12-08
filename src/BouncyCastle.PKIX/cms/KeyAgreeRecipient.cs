namespace org.bouncycastle.cms
{
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

	public interface KeyAgreeRecipient : Recipient
	{
		RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier contentEncryptionAlgorithm, SubjectPublicKeyInfo senderPublicKey, ASN1OctetString userKeyingMaterial, byte[] encryptedContentKey);

		AlgorithmIdentifier getPrivateKeyAlgorithmIdentifier();
	}

}