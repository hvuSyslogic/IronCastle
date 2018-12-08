namespace org.bouncycastle.cms
{
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;

	public class CMSConfig
	{
		/// <summary>
		/// Set the mapping for the encryption algorithm used in association with a SignedData generation
		/// or interpretation.
		/// </summary>
		/// <param name="oid"> object identifier to map. </param>
		/// <param name="algorithmName"> algorithm name to use. </param>
		public static void setSigningEncryptionAlgorithmMapping(string oid, string algorithmName)
		{
			ASN1ObjectIdentifier id = new ASN1ObjectIdentifier(oid);

			CMSSignedHelper.INSTANCE.setSigningEncryptionAlgorithmMapping(id, algorithmName);
		}

		/// <summary>
		/// Set the mapping for the digest algorithm to use in conjunction with a SignedData generation
		/// or interpretation.
		/// </summary>
		/// <param name="oid"> object identifier to map. </param>
		/// <param name="algorithmName"> algorithm name to use. </param>
		/// @deprecated no longer required. 
		public static void setSigningDigestAlgorithmMapping(string oid, string algorithmName)
		{
			ASN1ObjectIdentifier id = new ASN1ObjectIdentifier(oid);

			//CMSSignedHelper.INSTANCE.setSigningDigestAlgorithmMapping(id, algorithmName);
		}
	}

}