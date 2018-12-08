namespace org.bouncycastle.asn1.x509
{

	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// It turns out that the number of standard ways the fields in a DN should be 
	/// encoded into their ASN.1 counterparts is rapidly approaching the
	/// number of machines on the internet. By default the X509Name class 
	/// will produce UTF8Strings in line with the current recommendations (RFC 3280).
	/// <para>
	/// An example of an encoder look like below:
	/// <pre>
	/// public class X509DirEntryConverter
	///     extends X509NameEntryConverter
	/// {
	///     public ASN1Primitive getConvertedValue(
	///         ASN1ObjectIdentifier  oid,
	///         String               value)
	///     {
	///         if (str.length() != 0 &amp;&amp; str.charAt(0) == '#')
	///         {
	///             return convertHexEncoded(str, 1);
	///         }
	///         if (oid.equals(EmailAddress))
	///         {
	///             return new DERIA5String(str);
	///         }
	///         else if (canBePrintable(str))
	///         {
	///             return new DERPrintableString(str);
	///         }
	///         else if (canBeUTF8(str))
	///         {
	///             return new DERUTF8String(str);
	///         }
	///         else
	///         {
	///             return new DERBMPString(str);
	///         }
	///     }
	/// }
	/// </pre>
	/// </para>
	/// </summary>
	public abstract class X509NameEntryConverter
	{
		/// <summary>
		/// Convert an inline encoded hex string rendition of an ASN.1
		/// object back into its corresponding ASN.1 object.
		/// </summary>
		/// <param name="str"> the hex encoded object </param>
		/// <param name="off"> the index at which the encoding starts </param>
		/// <returns> the decoded object </returns>
		public virtual ASN1Primitive convertHexEncoded(string str, int off)
		{
			str = Strings.toLowerCase(str);
			byte[] data = new byte[(str.Length - off) / 2];
			for (int index = 0; index != data.Length; index++)
			{
				char left = str[(index * 2) + off];
				char right = str[(index * 2) + off + 1];

				if (left < 'a')
				{
					data[index] = (byte)((left - '0') << 4);
				}
				else
				{
					data[index] = (byte)((left - 'a' + 10) << 4);
				}
				if (right < 'a')
				{
					data[index] |= (byte)(right - '0');
				}
				else
				{
					data[index] |= (byte)(right - 'a' + 10);
				}
			}

			ASN1InputStream aIn = new ASN1InputStream(data);

			return aIn.readObject();
		}

		/// <summary>
		/// return true if the passed in String can be represented without
		/// loss as a PrintableString, false otherwise.
		/// </summary>
		public virtual bool canBePrintable(string str)
		{
			return DERPrintableString.isPrintableString(str);
		}

		/// <summary>
		/// Convert the passed in String value into the appropriate ASN.1
		/// encoded object.
		/// </summary>
		/// <param name="oid"> the oid associated with the value in the DN. </param>
		/// <param name="value"> the value of the particular DN component. </param>
		/// <returns> the ASN.1 equivalent for the value. </returns>
		public abstract ASN1Primitive getConvertedValue(ASN1ObjectIdentifier oid, string value);
	}

}