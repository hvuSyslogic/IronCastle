namespace org.bouncycastle.asn1.x500
{

	/// <summary>
	/// This interface provides a profile to conform to when
	/// DNs are being converted into strings and back. The idea being that we'll be able to deal with
	/// the number of standard ways the fields in a DN should be
	/// encoded into their ASN.1 counterparts - a number that is rapidly approaching the
	/// number of machines on the internet.
	/// </summary>
	public interface X500NameStyle
	{
		/// <summary>
		/// Convert the passed in String value into the appropriate ASN.1
		/// encoded object.
		/// </summary>
		/// <param name="oid"> the OID associated with the value in the DN. </param>
		/// <param name="value"> the value of the particular DN component. </param>
		/// <returns> the ASN.1 equivalent for the value. </returns>
		ASN1Encodable stringToValue(ASN1ObjectIdentifier oid, string value);

		/// <summary>
		/// Return the OID associated with the passed in name.
		/// </summary>
		/// <param name="attrName"> the string to match. </param>
		/// <returns> an OID </returns>
		ASN1ObjectIdentifier attrNameToOID(string attrName);

		/// <summary>
		/// Return an array of RDN generated from the passed in String. </summary>
		/// <param name="dirName">  the String representation. </param>
		/// <returns>  an array of corresponding RDNs. </returns>
		RDN[] fromString(string dirName);

		/// <summary>
		/// Return true if the two names are equal.
		/// </summary>
		/// <param name="name1"> first name for comparison. </param>
		/// <param name="name2"> second name for comparison. </param>
		/// <returns> true if name1 = name 2, false otherwise. </returns>
		bool areEqual(X500Name name1, X500Name name2);

		/// <summary>
		/// Calculate a hashCode for the passed in name.
		/// </summary>
		/// <param name="name"> the name the hashCode is required for. </param>
		/// <returns> the calculated hashCode. </returns>
		int calculateHashCode(X500Name name);

		/// <summary>
		/// Convert the passed in X500Name to a String. </summary>
		/// <param name="name"> the name to convert. </param>
		/// <returns> a String representation. </returns>
		string ToString(X500Name name);

		/// <summary>
		/// Return the display name for toString() associated with the OID.
		/// </summary>
		/// <param name="oid">  the OID of interest. </param>
		/// <returns> the name displayed in toString(), null if no mapping provided. </returns>
		string oidToDisplayName(ASN1ObjectIdentifier oid);

		/// <summary>
		/// Return the acceptable names in a String DN that map to OID.
		/// </summary>
		/// <param name="oid">  the OID of interest. </param>
		/// <returns> an array of String aliases for the OID, zero length if there are none. </returns>
		string[] oidToAttrNames(ASN1ObjectIdentifier oid);
	}
}