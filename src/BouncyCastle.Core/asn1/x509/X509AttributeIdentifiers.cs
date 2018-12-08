namespace org.bouncycastle.asn1.x509
{

	public interface X509AttributeIdentifiers
	{
		/// @deprecated use id_at_role 
		// { id-aca 5 } is reserved
	}

	public static class X509AttributeIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier RoleSyntax = new ASN1ObjectIdentifier("2.5.4.72");
		public static readonly ASN1ObjectIdentifier id_pe_ac_auditIdentity = X509ObjectIdentifiers_Fields.id_pe.branch("4");
		public static readonly ASN1ObjectIdentifier id_pe_aaControls = X509ObjectIdentifiers_Fields.id_pe.branch("6");
		public static readonly ASN1ObjectIdentifier id_pe_ac_proxying = X509ObjectIdentifiers_Fields.id_pe.branch("10");
		public static readonly ASN1ObjectIdentifier id_ce_targetInformation = X509ObjectIdentifiers_Fields.id_ce.branch("55");
		public static readonly ASN1ObjectIdentifier id_aca = X509ObjectIdentifiers_Fields.id_pkix.branch("10");
		public static readonly ASN1ObjectIdentifier id_aca_authenticationInfo = id_aca.branch("1");
		public static readonly ASN1ObjectIdentifier id_aca_accessIdentity = id_aca.branch("2");
		public static readonly ASN1ObjectIdentifier id_aca_chargingIdentity = id_aca.branch("3");
		public static readonly ASN1ObjectIdentifier id_aca_group = id_aca.branch("4");
		public static readonly ASN1ObjectIdentifier id_aca_encAttrs = id_aca.branch("6");
		public static readonly ASN1ObjectIdentifier id_at_role = new ASN1ObjectIdentifier("2.5.4.72");
		public static readonly ASN1ObjectIdentifier id_at_clearance = new ASN1ObjectIdentifier("2.5.1.5.55");
	}

}