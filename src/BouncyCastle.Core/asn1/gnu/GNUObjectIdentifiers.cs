namespace org.bouncycastle.asn1.gnu
{

	/// <summary>
	/// GNU project OID collection<para>
	/// { iso(1) identifier-organization(3) dod(6) internet(1) private(4) } == IETF defined things
	/// </para>
	/// </summary>
	public interface GNUObjectIdentifiers
	{
		/// <summary>
		/// 1.3.6.1.4.1.11591.1 -- used by GNU Radius
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.2 -- used by GNU PG
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.2.1 -- notation
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.2.1.1 -- pkaAddress
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.3 -- GNU Radar
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.12 -- digestAlgorithm
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.12.2 -- TIGER/192
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.13 -- encryptionAlgorithm
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.13.2 -- Serpent
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.13.2.1 -- Serpent-128-ECB
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.13.2.2 -- Serpent-128-CBC
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.13.2.3 -- Serpent-128-OFB
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.13.2.4 -- Serpent-128-CFB
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.13.2.21 -- Serpent-192-ECB
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.13.2.22 -- Serpent-192-CCB
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.13.2.23 -- Serpent-192-OFB
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.13.2.24 -- Serpent-192-CFB
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.13.2.41 -- Serpent-256-ECB
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.13.2.42 -- Serpent-256-CBC
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.13.2.43 -- Serpent-256-OFB
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.13.2.44 -- Serpent-256-CFB
		/// </summary>

		/// <summary>
		/// 1.3.6.1.4.1.11591.14 -- CRC algorithms
		/// </summary>
		/// <summary>
		/// 1.3.6.1.4.1.11591.14,1 -- CRC32
		/// </summary>

		/// <summary>
		/// 1.3.6.1.4.1.11591.15 - ellipticCurve
		/// </summary>
	}

	public static class GNUObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier GNU = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.1");
		public static readonly ASN1ObjectIdentifier GnuPG = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.2");
		public static readonly ASN1ObjectIdentifier notation = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.2.1");
		public static readonly ASN1ObjectIdentifier pkaAddress = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.2.1.1");
		public static readonly ASN1ObjectIdentifier GnuRadar = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.3");
		public static readonly ASN1ObjectIdentifier digestAlgorithm = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.12");
		public static readonly ASN1ObjectIdentifier Tiger_192 = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.12.2");
		public static readonly ASN1ObjectIdentifier encryptionAlgorithm = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13");
		public static readonly ASN1ObjectIdentifier Serpent = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2");
		public static readonly ASN1ObjectIdentifier Serpent_128_ECB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.1");
		public static readonly ASN1ObjectIdentifier Serpent_128_CBC = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.2");
		public static readonly ASN1ObjectIdentifier Serpent_128_OFB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.3");
		public static readonly ASN1ObjectIdentifier Serpent_128_CFB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.4");
		public static readonly ASN1ObjectIdentifier Serpent_192_ECB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.21");
		public static readonly ASN1ObjectIdentifier Serpent_192_CBC = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.22");
		public static readonly ASN1ObjectIdentifier Serpent_192_OFB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.23");
		public static readonly ASN1ObjectIdentifier Serpent_192_CFB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.24");
		public static readonly ASN1ObjectIdentifier Serpent_256_ECB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.41");
		public static readonly ASN1ObjectIdentifier Serpent_256_CBC = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.42");
		public static readonly ASN1ObjectIdentifier Serpent_256_OFB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.43");
		public static readonly ASN1ObjectIdentifier Serpent_256_CFB = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.13.2.44");
		public static readonly ASN1ObjectIdentifier CRC = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.14");
		public static readonly ASN1ObjectIdentifier CRC32 = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.14.1");
		public static readonly ASN1ObjectIdentifier ellipticCurve = new ASN1ObjectIdentifier("1.3.6.1.4.1.11591.15");
		public static readonly ASN1ObjectIdentifier Ed25519 = ellipticCurve.branch("1");
	}

}