namespace org.bouncycastle.asn1
{
	/// <summary>
	/// Supported encoding formats.
	/// </summary>
	public interface ASN1Encoding
	{
		/// <summary>
		/// DER - distinguished encoding rules.
		/// </summary>

		/// <summary>
		/// DL - definite length encoding.
		/// </summary>

		/// <summary>
		/// BER - basic encoding rules.
		/// </summary>
	}

	public static class ASN1Encoding_Fields
	{
		public const string DER = "DER";
		public const string DL = "DL";
		public const string BER = "BER";
	}

}