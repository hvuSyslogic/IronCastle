namespace org.bouncycastle.cms
{
	using RecipientInfo = org.bouncycastle.asn1.cms.RecipientInfo;
	using GenericKey = org.bouncycastle.@operator.GenericKey;

	public interface RecipientInfoGenerator
	{
		RecipientInfo generate(GenericKey contentEncryptionKey);
	}

}