using System.IO;
using org.bouncycastle.Port;

namespace org.bouncycastle.asn1.x509
{


	/// <summary>
	/// The default converter for X509 DN entries when going from their
	/// string value to ASN.1 strings.
	/// </summary>
	public class X509DefaultEntryConverter : X509NameEntryConverter
	{
		/// <summary>
		/// Apply default coversion for the given value depending on the oid
		/// and the character range of the value.
		/// </summary>
		/// <param name="oid"> the object identifier for the DN entry </param>
		/// <param name="value"> the value associated with it </param>
		/// <returns> the ASN.1 equivalent for the string value. </returns>
		public override ASN1Primitive getConvertedValue(ASN1ObjectIdentifier oid, string value)
		{
			if (value.Length != 0 && value[0] == '#')
			{
				try
				{
					return convertHexEncoded(value, 1);
				}
				catch (IOException)
				{
					throw new RuntimeException("can't recode value for oid " + oid.getId());
				}
			}
			else
			{
				if (value.Length != 0 && value[0] == '\\')
				{
					value = value.Substring(1);
				}
				if (oid.Equals(X509Name.EmailAddress) || oid.Equals(X509Name.DC))
				{
					return new DERIA5String(value);
				}
				else if (oid.Equals(X509Name.DATE_OF_BIRTH)) // accept time string as well as # (for compatibility)
				{
					return new DERGeneralizedTime(value);
				}
				else if (oid.Equals(X509Name.C) || oid.Equals(X509Name.SN) || oid.Equals(X509Name.DN_QUALIFIER) || oid.Equals(X509Name.TELEPHONE_NUMBER))
				{
					 return new DERPrintableString(value);
				}
			}

			return new DERUTF8String(value);
		}
	}

}