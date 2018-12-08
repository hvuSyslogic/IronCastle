using org.bouncycastle.asn1.crmf;

namespace org.bouncycastle.cert.crmf
{
	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERUTF8String = org.bouncycastle.asn1.DERUTF8String;
	using CRMFObjectIdentifiers = org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;

	/// <summary>
	/// Carrier for a registration token control.
	/// </summary>
	public class RegTokenControl : Control
	{
		private static readonly ASN1ObjectIdentifier type = CRMFObjectIdentifiers_Fields.id_regCtrl_regToken;

		private readonly DERUTF8String token;

		/// <summary>
		/// Basic constructor - build from a UTF-8 string representing the token.
		/// </summary>
		/// <param name="token"> UTF-8 string representing the token. </param>
		public RegTokenControl(DERUTF8String token)
		{
			this.token = token;
		}

		/// <summary>
		/// Basic constructor - build from a string representing the token.
		/// </summary>
		/// <param name="token"> string representing the token. </param>
		public RegTokenControl(string token)
		{
			this.token = new DERUTF8String(token);
		}

		/// <summary>
		/// Return the type of this control.
		/// </summary>
		/// <returns> CRMFObjectIdentifiers.id_regCtrl_regToken </returns>
		public virtual ASN1ObjectIdentifier getType()
		{
			return type;
		}

		/// <summary>
		/// Return the token associated with this control (a UTF8String).
		/// </summary>
		/// <returns> a UTF8String. </returns>
		public virtual ASN1Encodable getValue()
		{
			return token;
		}
	}

}