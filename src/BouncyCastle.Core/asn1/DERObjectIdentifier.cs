namespace org.bouncycastle.asn1
{
	/// 
	/// @deprecated Use ASN1ObjectIdentifier instead of this, 
	public class DERObjectIdentifier : ASN1ObjectIdentifier
	{
		public DERObjectIdentifier(string identifier) : base(identifier)
		{
		}

		public DERObjectIdentifier(byte[] bytes) : base(bytes)
		{
		}

		public DERObjectIdentifier(ASN1ObjectIdentifier oid, string branch) : base(oid, branch)
		{
		}
	}

}