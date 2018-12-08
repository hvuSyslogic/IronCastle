namespace org.bouncycastle.asn1.smime
{
	using Attribute = org.bouncycastle.asn1.cms.Attribute;
	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using RecipientKeyIdentifier = org.bouncycastle.asn1.cms.RecipientKeyIdentifier;

	/// <summary>
	/// The SMIMEEncryptionKeyPreference object.
	/// <pre>
	/// SMIMEEncryptionKeyPreference ::= CHOICE {
	///     issuerAndSerialNumber   [0] IssuerAndSerialNumber,
	///     receipentKeyId          [1] RecipientKeyIdentifier,
	///     subjectAltKeyIdentifier [2] SubjectKeyIdentifier
	/// }
	/// </pre>
	/// </summary>
	public class SMIMEEncryptionKeyPreferenceAttribute : Attribute
	{
		public SMIMEEncryptionKeyPreferenceAttribute(IssuerAndSerialNumber issAndSer) : base(SMIMEAttributes_Fields.encrypKeyPref, new DERSet(new DERTaggedObject(false, 0, issAndSer)))
		{
		}

		public SMIMEEncryptionKeyPreferenceAttribute(RecipientKeyIdentifier rKeyId) : base(SMIMEAttributes_Fields.encrypKeyPref, new DERSet(new DERTaggedObject(false, 1, rKeyId)))
		{

		}

		/// <param name="sKeyId"> the subjectKeyIdentifier value (normally the X.509 one) </param>
		public SMIMEEncryptionKeyPreferenceAttribute(ASN1OctetString sKeyId) : base(SMIMEAttributes_Fields.encrypKeyPref, new DERSet(new DERTaggedObject(false, 2, sKeyId)))
		{

		}
	}

}