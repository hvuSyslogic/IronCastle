namespace org.bouncycastle.jce.interfaces
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;

	/// <summary>
	/// allow us to set attributes on objects that can go into a PKCS12 store.
	/// </summary>
	public interface PKCS12BagAttributeCarrier
	{
		void setBagAttribute(ASN1ObjectIdentifier oid, ASN1Encodable attribute);

		ASN1Encodable getBagAttribute(ASN1ObjectIdentifier oid);

		Enumeration getBagAttributeKeys();
	}

}