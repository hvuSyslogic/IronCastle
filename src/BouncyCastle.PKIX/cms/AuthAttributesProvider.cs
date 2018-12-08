namespace org.bouncycastle.cms
{
	using ASN1Set = org.bouncycastle.asn1.ASN1Set;

	public interface AuthAttributesProvider
	{
		ASN1Set getAuthAttributes();
	}

}