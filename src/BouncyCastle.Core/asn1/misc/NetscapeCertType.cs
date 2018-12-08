namespace org.bouncycastle.asn1.misc
{

	/// <summary>
	/// The NetscapeCertType object.
	/// <pre>
	///    NetscapeCertType ::= BIT STRING {
	///         SSLClient               (0),
	///         SSLServer               (1),
	///         S/MIME                  (2),
	///         Object Signing          (3),
	///         Reserved                (4),
	///         SSL CA                  (5),
	///         S/MIME CA               (6),
	///         Object Signing CA       (7) }
	/// </pre>
	/// </summary>
	public class NetscapeCertType : DERBitString
	{
		public static readonly int sslClient = (1 << 7);
		public static readonly int sslServer = (1 << 6);
		public static readonly int smime = (1 << 5);
		public static readonly int objectSigning = (1 << 4);
		public static readonly int reserved = (1 << 3);
		public static readonly int sslCA = (1 << 2);
		public static readonly int smimeCA = (1 << 1);
		public static readonly int objectSigningCA = (1 << 0);

		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="usage"> - the bitwise OR of the Key Usage flags giving the
		/// allowed uses for the key.
		/// e.g. (X509NetscapeCertType.sslCA | X509NetscapeCertType.smimeCA) </param>
		public NetscapeCertType(int usage) : base(getBytes(usage), getPadBits(usage))
		{
		}

		public NetscapeCertType(DERBitString usage) : base(usage.getBytes(), usage.getPadBits())
		{
		}

		public override string ToString()
		{
			return "NetscapeCertType: 0x" + (data[0] & 0xff).ToString("x");
		}
	}

}