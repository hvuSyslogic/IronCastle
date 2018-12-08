using org.bouncycastle.asn1.sec;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.nist
{

	using SECNamedCurves = org.bouncycastle.asn1.sec.SECNamedCurves;
	using SECObjectIdentifiers = org.bouncycastle.asn1.sec.SECObjectIdentifiers;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Utility class for fetching curves using their NIST names as published in FIPS-PUB 186-3
	/// </summary>
	public class NISTNamedCurves
	{
		internal static readonly Hashtable objIds = new Hashtable();
		internal static readonly Hashtable names = new Hashtable();

		internal static void defineCurve(string name, ASN1ObjectIdentifier oid)
		{
			objIds.put(name, oid);
			names.put(oid, name);
		}

		static NISTNamedCurves()
		{
			defineCurve("B-571", SECObjectIdentifiers_Fields.sect571r1);
			defineCurve("B-409", SECObjectIdentifiers_Fields.sect409r1);
			defineCurve("B-283", SECObjectIdentifiers_Fields.sect283r1);
			defineCurve("B-233", SECObjectIdentifiers_Fields.sect233r1);
			defineCurve("B-163", SECObjectIdentifiers_Fields.sect163r2);
			defineCurve("K-571", SECObjectIdentifiers_Fields.sect571k1);
			defineCurve("K-409", SECObjectIdentifiers_Fields.sect409k1);
			defineCurve("K-283", SECObjectIdentifiers_Fields.sect283k1);
			defineCurve("K-233", SECObjectIdentifiers_Fields.sect233k1);
			defineCurve("K-163", SECObjectIdentifiers_Fields.sect163k1);
			defineCurve("P-521", SECObjectIdentifiers_Fields.secp521r1);
			defineCurve("P-384", SECObjectIdentifiers_Fields.secp384r1);
			defineCurve("P-256", SECObjectIdentifiers_Fields.secp256r1);
			defineCurve("P-224", SECObjectIdentifiers_Fields.secp224r1);
			defineCurve("P-192", SECObjectIdentifiers_Fields.secp192r1);
		}

		public static X9ECParameters getByName(string name)
		{
			ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)objIds.get(Strings.toUpperCase(name));

			if (oid != null)
			{
				return getByOID(oid);
			}

			return null;
		}

		/// <summary>
		/// return the X9ECParameters object for the named curve represented by
		/// the passed in object identifier. Null if the curve isn't present.
		/// </summary>
		/// <param name="oid"> an object identifier representing a named curve, if present. </param>
		public static X9ECParameters getByOID(ASN1ObjectIdentifier oid)
		{
			return SECNamedCurves.getByOID(oid);
		}

		/// <summary>
		/// return the object identifier signified by the passed in name. Null
		/// if there is no object identifier associated with name.
		/// </summary>
		/// <returns> the object identifier associated with name, if present. </returns>
		public static ASN1ObjectIdentifier getOID(string name)
		{
			return (ASN1ObjectIdentifier)objIds.get(Strings.toUpperCase(name));
		}

		/// <summary>
		/// return the named curve name represented by the given object identifier.
		/// </summary>
		public static string getName(ASN1ObjectIdentifier oid)
		{
			return (string)names.get(oid);
		}

		/// <summary>
		/// returns an enumeration containing the name strings for curves
		/// contained in this structure.
		/// </summary>
		public static Enumeration getNames()
		{
			return objIds.keys();
		}
	}

}