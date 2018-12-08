namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Carrier class for a DER encoding OCTET STRING
	/// </summary>
	public class DEROctetString : ASN1OctetString
	{
		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="string"> the octets making up the octet string. </param>
		public DEROctetString(byte[] @string) : base(@string)
		{
		}

		/// <summary>
		/// Constructor from the encoding of an ASN.1 object.
		/// </summary>
		/// <param name="obj"> the object to be encoded. </param>
		public DEROctetString(ASN1Encodable obj) : base(obj.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER))
		{
		}

		public override bool isConstructed()
		{
			return false;
		}

		public override int encodedLength()
		{
			return 1 + StreamUtil.calculateBodyLength(@string.Length) + @string.Length;
		}

		public override void encode(ASN1OutputStream @out)
		{
			@out.writeEncoded(BERTags_Fields.OCTET_STRING, @string);
		}

		internal static void encode(DEROutputStream derOut, byte[] bytes)
		{
			derOut.writeEncoded(BERTags_Fields.OCTET_STRING, bytes);
		}
	}

}