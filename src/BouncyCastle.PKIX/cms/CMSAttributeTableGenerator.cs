namespace org.bouncycastle.cms
{

	using AttributeTable = org.bouncycastle.asn1.cms.AttributeTable;

	/// <summary>
	/// Note: The SIGNATURE parameter is only available when generating unsigned attributes.
	/// </summary>
	public interface CMSAttributeTableGenerator
	{

		AttributeTable getAttributes(Map parameters);
	}

	public static class CMSAttributeTableGenerator_Fields
	{
		public const string CONTENT_TYPE = "contentType";
		public const string DIGEST = "digest";
		public const string SIGNATURE = "encryptedDigest";
		public const string DIGEST_ALGORITHM_IDENTIFIER = "digestAlgID";
		public const string MAC_ALGORITHM_IDENTIFIER = "macAlgID";
		public const string SIGNATURE_ALGORITHM_IDENTIFIER = "signatureAlgID";
	}

}