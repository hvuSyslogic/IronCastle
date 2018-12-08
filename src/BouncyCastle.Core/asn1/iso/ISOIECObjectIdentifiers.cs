namespace org.bouncycastle.asn1.iso
{

	/// <summary>
	/// OIDS from  ISO/IEC 10118-3:2004
	/// </summary>
	public interface ISOIECObjectIdentifiers
	{



		/// <summary>
		///   -- ISO/IEC 18033-2 arc
		/// 
		///    is18033-2 OID ::= { iso(1) standard(0) is18033(18033) part2(2) }
		/// </summary>

		/// <summary>
		/// id-kem-rsa OID ::= {
		///   is18033-2 key-encapsulation-mechanism(2) rsa(4)
		/// }
		/// </summary>
	}

	public static class ISOIECObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier iso_encryption_algorithms = new ASN1ObjectIdentifier("1.0.10118");
		public static readonly ASN1ObjectIdentifier hash_algorithms = iso_encryption_algorithms.branch("3.0");
		public static readonly ASN1ObjectIdentifier ripemd160 = hash_algorithms.branch("49");
		public static readonly ASN1ObjectIdentifier ripemd128 = hash_algorithms.branch("50");
		public static readonly ASN1ObjectIdentifier whirlpool = hash_algorithms.branch("55");
		public static readonly ASN1ObjectIdentifier is18033_2 = new ASN1ObjectIdentifier("1.0.18033.2");
		public static readonly ASN1ObjectIdentifier id_ac_generic_hybrid = is18033_2.branch("1.2");
		public static readonly ASN1ObjectIdentifier id_kem_rsa = is18033_2.branch("2.4");
	}

}