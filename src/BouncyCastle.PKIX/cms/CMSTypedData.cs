namespace org.bouncycastle.cms
{
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;

	public interface CMSTypedData : CMSProcessable
	{
		ASN1ObjectIdentifier getContentType();
	}

}