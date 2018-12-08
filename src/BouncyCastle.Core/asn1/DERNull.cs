namespace org.bouncycastle.asn1
{

	/// <summary>
	/// An ASN.1 DER NULL object.
	/// <para>
	/// Preferably use the constant:  DERNull.INSTANCE.
	/// </para>
	/// </summary>
	public class DERNull : ASN1Null
	{
		public static readonly DERNull INSTANCE = new DERNull();

		private static readonly byte[] zeroBytes = new byte[0];

		/// @deprecated use DERNull.INSTANCE 
		public DERNull()
		{
		}

		public override bool isConstructed()
		{
			return false;
		}

		public override int encodedLength()
		{
			return 2;
		}

		public override void encode(ASN1OutputStream @out)
		{
			@out.writeEncoded(BERTags_Fields.NULL, zeroBytes);
		}
	}

}