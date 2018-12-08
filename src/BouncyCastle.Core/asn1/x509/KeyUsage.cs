namespace org.bouncycastle.asn1.x509
{

	/// <summary>
	/// The KeyUsage object.
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
	public class KeyUsage : ASN1Object
	{
		public static readonly int digitalSignature = (1 << 7);
		public static readonly int nonRepudiation = (1 << 6);
		public static readonly int keyEncipherment = (1 << 5);
		public static readonly int dataEncipherment = (1 << 4);
		public static readonly int keyAgreement = (1 << 3);
		public static readonly int keyCertSign = (1 << 2);
		public static readonly int cRLSign = (1 << 1);
		public static readonly int encipherOnly = (1 << 0);
		public static readonly int decipherOnly = (1 << 15);

		private DERBitString bitString;

		public static KeyUsage getInstance(object obj) // needs to be DERBitString for other VMs
		{
			if (obj is KeyUsage)
			{
				return (KeyUsage)obj;
			}
			else if (obj != null)
			{
				return new KeyUsage(DERBitString.getInstance(obj));
			}

			return null;
		}

		public static KeyUsage fromExtensions(Extensions extensions)
		{
			return KeyUsage.getInstance(extensions.getExtensionParsedValue(Extension.keyUsage));
		}

		/// <summary>
		/// Basic constructor.
		/// </summary>
		/// <param name="usage"> - the bitwise OR of the Key Usage flags giving the
		/// allowed uses for the key.
		/// e.g. (KeyUsage.keyEncipherment | KeyUsage.dataEncipherment) </param>
		public KeyUsage(int usage)
		{
			this.bitString = new DERBitString(usage);
		}

		private KeyUsage(DERBitString bitString)
		{
			this.bitString = bitString;
		}

		/// <summary>
		/// Return true if a given usage bit is set, false otherwise.
		/// </summary>
		/// <param name="usages"> combination of usage flags. </param>
		/// <returns> true if all bits are set, false otherwise. </returns>
		public virtual bool hasUsages(int usages)
		{
			return (bitString.intValue() & usages) == usages;
		}

		public virtual byte[] getBytes()
		{
			return bitString.getBytes();
		}

		public virtual int getPadBits()
		{
			return bitString.getPadBits();
		}

		public override string ToString()
		{
			byte[] data = bitString.getBytes();

			if (data.Length == 1)
			{
				return "KeyUsage: 0x" + (data[0] & 0xff).ToString("x");
			}
			return "KeyUsage: 0x" + ((data[1] & 0xff) << 8 | (data[0] & 0xff)).ToString("x");
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return bitString;
		}
	}

}