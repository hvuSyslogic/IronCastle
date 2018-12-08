namespace org.bouncycastle.asn1.x509.sigi
{

	/// <summary>
	/// Object Identifiers of SigI specifciation (German Signature Law
	/// Interoperability specification).
	/// </summary>
	public interface SigIObjectIdentifiers
	{
		/// <summary>
		/// OID: 1.3.36.8
		/// </summary>

		/// <summary>
		/// Key purpose IDs for German SigI (Signature Interoperability
		/// Specification)
		/// <para>
		/// OID: 1.3.36.8.2
		/// </para>
		/// </summary>

		/// <summary>
		/// Certificate policy IDs for German SigI (Signature Interoperability
		/// Specification)
		/// <para>
		/// OID: 1.3.36.8.1
		/// </para>
		/// </summary>

		/// <summary>
		/// Other Name IDs for German SigI (Signature Interoperability Specification)
		/// <para>
		/// OID: 1.3.36.8.4
		/// </para>
		/// </summary>

		/// <summary>
		/// To be used for for the generation of directory service certificates.
		/// <para>
		/// OID: 1.3.36.8.2.1
		/// </para>
		/// </summary>

		/// <summary>
		/// ID for PersonalData
		/// <para>
		/// OID: 1.3.36.8.4.1
		/// </para>
		/// </summary>

		/// <summary>
		/// Certificate is conformant to german signature law.
		/// <para>
		/// OID: 1.3.36.8.1.1
		/// </para>
		/// </summary>

	}

	public static class SigIObjectIdentifiers_Fields
	{
		public static readonly ASN1ObjectIdentifier id_sigi = new ASN1ObjectIdentifier("1.3.36.8");
		public static readonly ASN1ObjectIdentifier id_sigi_kp = new ASN1ObjectIdentifier("1.3.36.8.2");
		public static readonly ASN1ObjectIdentifier id_sigi_cp = new ASN1ObjectIdentifier("1.3.36.8.1");
		public static readonly ASN1ObjectIdentifier id_sigi_on = new ASN1ObjectIdentifier("1.3.36.8.4");
		public static readonly ASN1ObjectIdentifier id_sigi_kp_directoryService = new ASN1ObjectIdentifier("1.3.36.8.2.1");
		public static readonly ASN1ObjectIdentifier id_sigi_on_personalData = new ASN1ObjectIdentifier("1.3.36.8.4.1");
		public static readonly ASN1ObjectIdentifier id_sigi_cp_sigconform = new ASN1ObjectIdentifier("1.3.36.8.1.1");
	}

}