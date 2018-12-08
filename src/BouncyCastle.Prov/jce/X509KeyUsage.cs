namespace org.bouncycastle.jce
{
	using ASN1Object = org.bouncycastle.asn1.ASN1Object;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using KeyUsage = org.bouncycastle.asn1.x509.KeyUsage;

	/// <summary>
	/// A holding class for constructing an X509 Key Usage extension.
	/// 
	/// <pre>
	///    id-ce-keyUsage OBJECT IDENTIFIER ::=  { id-ce 15 }
	/// 
	///    KeyUsage ::= BIT STRING {
	///         digitalSignature        (0),
	///         nonRepudiation          (1),
	///         keyEncipherment         (2),
	///         dataEncipherment        (3),
	///         keyAgreement            (4),
	///         keyCertSign             (5),
	///         cRLSign                 (6),
	///         encipherOnly            (7),
	///         decipherOnly            (8) }
	/// </pre>
	/// </summary>
	public class X509KeyUsage : ASN1Object
	{
		public static readonly int digitalSignature = 1 << 7;
		public static readonly int nonRepudiation = 1 << 6;
		public static readonly int keyEncipherment = 1 << 5;
		public static readonly int dataEncipherment = 1 << 4;
		public static readonly int keyAgreement = 1 << 3;
		public static readonly int keyCertSign = 1 << 2;
		public static readonly int cRLSign = 1 << 1;
		public static readonly int encipherOnly = 1 << 0;
		public static readonly int decipherOnly = 1 << 15;

		private int usage = 0;

		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="usage"> - the bitwise OR of the Key Usage flags giving the
		/// allowed uses for the key.
		/// e.g. (X509KeyUsage.keyEncipherment | X509KeyUsage.dataEncipherment) </param>
		public X509KeyUsage(int usage)
		{
			this.usage = usage;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return (new KeyUsage(usage)).toASN1Primitive();
		}
	}

}