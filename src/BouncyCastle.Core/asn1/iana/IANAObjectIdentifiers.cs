namespace org.bouncycastle.asn1.iana
{

	/// <summary>
	/// IANA:
	///  { iso(1) identifier-organization(3) dod(6) internet(1) } == IETF defined things
	/// </summary>
	public interface IANAObjectIdentifiers
	{

		/// <summary>
		/// { iso(1) identifier-organization(3) dod(6) internet(1) } == IETF defined things </summary>
		/// <summary>
		/// 1.3.6.1.1: Internet directory: X.500 </summary>
		/// <summary>
		/// 1.3.6.1.2: Internet management </summary>
		/// <summary>
		/// 1.3.6.1.3: </summary>
		/// <summary>
		/// 1.3.6.1.4: </summary>
		/// <summary>
		/// 1.3.6.1.5: Security services </summary>
		/// <summary>
		/// 1.3.6.1.6: SNMPv2 -- never really used </summary>
		/// <summary>
		/// 1.3.6.1.7: mail -- never really used </summary>


		// id-SHA1 OBJECT IDENTIFIER ::=    
		// {iso(1) identified-organization(3) dod(6) internet(1) security(5) mechanisms(5) ipsec(8) isakmpOakley(1)}
		//


		/// <summary>
		/// IANA security mechanisms; 1.3.6.1.5.5 </summary>
		/// <summary>
		/// IANA security nametypes;  1.3.6.1.5.6 </summary>

		/// <summary>
		/// PKIX base OID:            1.3.6.1.5.6.6 </summary>


		/// <summary>
		/// IPSEC base OID:                        1.3.6.1.5.5.8 </summary>
		/// <summary>
		/// IPSEC ISAKMP-Oakley OID:               1.3.6.1.5.5.8.1 </summary>

		/// <summary>
		/// IPSEC ISAKMP-Oakley hmacMD5 OID:       1.3.6.1.5.5.8.1.1 </summary>
		/// <summary>
		/// IPSEC ISAKMP-Oakley hmacSHA1 OID:      1.3.6.1.5.5.8.1.2 </summary>

		/// <summary>
		/// IPSEC ISAKMP-Oakley hmacTIGER OID:     1.3.6.1.5.5.8.1.3 </summary>

		/// <summary>
		/// IPSEC ISAKMP-Oakley hmacRIPEMD160 OID: 1.3.6.1.5.5.8.1.4 </summary>

	}

	public static class IANAObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier internet = new ASN1ObjectIdentifier("1.3.6.1");
		public static readonly ASN1ObjectIdentifier directory = internet.branch("1");
		public static readonly ASN1ObjectIdentifier mgmt = internet.branch("2");
		public static readonly ASN1ObjectIdentifier experimental = internet.branch("3");
		public static readonly ASN1ObjectIdentifier _private = internet.branch("4");
		public static readonly ASN1ObjectIdentifier security = internet.branch("5");
		public static readonly ASN1ObjectIdentifier SNMPv2 = internet.branch("6");
		public static readonly ASN1ObjectIdentifier mail = internet.branch("7");
		public static readonly ASN1ObjectIdentifier security_mechanisms = security.branch("5");
		public static readonly ASN1ObjectIdentifier security_nametypes = security.branch("6");
		public static readonly ASN1ObjectIdentifier pkix = security_mechanisms.branch("6");
		public static readonly ASN1ObjectIdentifier ipsec = security_mechanisms.branch("8");
		public static readonly ASN1ObjectIdentifier isakmpOakley = ipsec.branch("1");
		public static readonly ASN1ObjectIdentifier hmacMD5 = isakmpOakley.branch("1");
		public static readonly ASN1ObjectIdentifier hmacSHA1 = isakmpOakley.branch("2");
		public static readonly ASN1ObjectIdentifier hmacTIGER = isakmpOakley.branch("3");
		public static readonly ASN1ObjectIdentifier hmacRIPEMD160 = isakmpOakley.branch("4");
	}

}