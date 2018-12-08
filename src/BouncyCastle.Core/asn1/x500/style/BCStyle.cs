using org.bouncycastle.asn1.x509;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x500.style
{

	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

	public class BCStyle : AbstractX500NameStyle
	{
		/// <summary>
		/// country code - StringType(SIZE(2))
		/// </summary>
		public static readonly ASN1ObjectIdentifier C = new ASN1ObjectIdentifier("2.5.4.6").intern();

		/// <summary>
		/// organization - StringType(SIZE(1..64))
		/// </summary>
		public static readonly ASN1ObjectIdentifier O = new ASN1ObjectIdentifier("2.5.4.10").intern();

		/// <summary>
		/// organizational unit name - StringType(SIZE(1..64))
		/// </summary>
		public static readonly ASN1ObjectIdentifier OU = new ASN1ObjectIdentifier("2.5.4.11").intern();

		/// <summary>
		/// Title
		/// </summary>
		public static readonly ASN1ObjectIdentifier T = new ASN1ObjectIdentifier("2.5.4.12").intern();

		/// <summary>
		/// common name - StringType(SIZE(1..64))
		/// </summary>
		public static readonly ASN1ObjectIdentifier CN = new ASN1ObjectIdentifier("2.5.4.3").intern();

		/// <summary>
		/// device serial number name - StringType(SIZE(1..64))
		/// </summary>
		public static readonly ASN1ObjectIdentifier SN = new ASN1ObjectIdentifier("2.5.4.5").intern();

		/// <summary>
		/// street - StringType(SIZE(1..64))
		/// </summary>
		public static readonly ASN1ObjectIdentifier STREET = new ASN1ObjectIdentifier("2.5.4.9").intern();

		/// <summary>
		/// device serial number name - StringType(SIZE(1..64))
		/// </summary>
		public static readonly ASN1ObjectIdentifier SERIALNUMBER = SN;

		/// <summary>
		/// locality name - StringType(SIZE(1..64))
		/// </summary>
		public static readonly ASN1ObjectIdentifier L = new ASN1ObjectIdentifier("2.5.4.7").intern();

		/// <summary>
		/// state, or province name - StringType(SIZE(1..64))
		/// </summary>
		public static readonly ASN1ObjectIdentifier ST = new ASN1ObjectIdentifier("2.5.4.8").intern();

		/// <summary>
		/// Naming attributes of type X520name
		/// </summary>
		public static readonly ASN1ObjectIdentifier SURNAME = new ASN1ObjectIdentifier("2.5.4.4").intern();
		public static readonly ASN1ObjectIdentifier GIVENNAME = new ASN1ObjectIdentifier("2.5.4.42").intern();
		public static readonly ASN1ObjectIdentifier INITIALS = new ASN1ObjectIdentifier("2.5.4.43").intern();
		public static readonly ASN1ObjectIdentifier GENERATION = new ASN1ObjectIdentifier("2.5.4.44").intern();
		public static readonly ASN1ObjectIdentifier UNIQUE_IDENTIFIER = new ASN1ObjectIdentifier("2.5.4.45").intern();

		/// <summary>
		/// businessCategory - DirectoryString(SIZE(1..128)
		/// </summary>
		public static readonly ASN1ObjectIdentifier BUSINESS_CATEGORY = new ASN1ObjectIdentifier("2.5.4.15").intern();

		/// <summary>
		/// postalCode - DirectoryString(SIZE(1..40)
		/// </summary>
		public static readonly ASN1ObjectIdentifier POSTAL_CODE = new ASN1ObjectIdentifier("2.5.4.17").intern();

		/// <summary>
		/// dnQualifier - DirectoryString(SIZE(1..64)
		/// </summary>
		public static readonly ASN1ObjectIdentifier DN_QUALIFIER = new ASN1ObjectIdentifier("2.5.4.46").intern();

		/// <summary>
		/// RFC 3039 Pseudonym - DirectoryString(SIZE(1..64)
		/// </summary>
		public static readonly ASN1ObjectIdentifier PSEUDONYM = new ASN1ObjectIdentifier("2.5.4.65").intern();


		/// <summary>
		/// RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z
		/// </summary>
		public static readonly ASN1ObjectIdentifier DATE_OF_BIRTH = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1").intern();

		/// <summary>
		/// RFC 3039 PlaceOfBirth - DirectoryString(SIZE(1..128)
		/// </summary>
		public static readonly ASN1ObjectIdentifier PLACE_OF_BIRTH = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.2").intern();

		/// <summary>
		/// RFC 3039 Gender - PrintableString (SIZE(1)) -- "M", "F", "m" or "f"
		/// </summary>
		public static readonly ASN1ObjectIdentifier GENDER = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.3").intern();

		/// <summary>
		/// RFC 3039 CountryOfCitizenship - PrintableString (SIZE (2)) -- ISO 3166
		/// codes only
		/// </summary>
		public static readonly ASN1ObjectIdentifier COUNTRY_OF_CITIZENSHIP = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.4").intern();

		/// <summary>
		/// RFC 3039 CountryOfResidence - PrintableString (SIZE (2)) -- ISO 3166
		/// codes only
		/// </summary>
		public static readonly ASN1ObjectIdentifier COUNTRY_OF_RESIDENCE = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.5").intern();


		/// <summary>
		/// ISIS-MTT NameAtBirth - DirectoryString(SIZE(1..64)
		/// </summary>
		public static readonly ASN1ObjectIdentifier NAME_AT_BIRTH = new ASN1ObjectIdentifier("1.3.36.8.3.14").intern();

		/// <summary>
		/// RFC 3039 PostalAddress - SEQUENCE SIZE (1..6) OF
		/// DirectoryString(SIZE(1..30))
		/// </summary>
		public static readonly ASN1ObjectIdentifier POSTAL_ADDRESS = new ASN1ObjectIdentifier("2.5.4.16").intern();

		/// <summary>
		/// RFC 2256 dmdName
		/// </summary>
		public static readonly ASN1ObjectIdentifier DMD_NAME = new ASN1ObjectIdentifier("2.5.4.54").intern();

		/// <summary>
		/// id-at-telephoneNumber
		/// </summary>
		public static readonly ASN1ObjectIdentifier TELEPHONE_NUMBER = X509ObjectIdentifiers_Fields.id_at_telephoneNumber;

		/// <summary>
		/// id-at-name
		/// </summary>
		public static readonly ASN1ObjectIdentifier NAME = X509ObjectIdentifiers_Fields.id_at_name;


		/// <summary>
		/// id-at-organizationIdentifier
		/// </summary>
		public static readonly ASN1ObjectIdentifier ORGANIZATION_IDENTIFIER = X509ObjectIdentifiers_Fields.id_at_organizationIdentifier;

		/// <summary>
		/// Email address (RSA PKCS#9 extension) - IA5String.
		/// <para>Note: if you're trying to be ultra orthodox, don't use this! It shouldn't be in here.
		/// </para>
		/// </summary>
		public static readonly ASN1ObjectIdentifier EmailAddress = PKCSObjectIdentifiers_Fields.pkcs_9_at_emailAddress;

		/// <summary>
		/// more from PKCS#9
		/// </summary>
		public static readonly ASN1ObjectIdentifier UnstructuredName = PKCSObjectIdentifiers_Fields.pkcs_9_at_unstructuredName;
		public static readonly ASN1ObjectIdentifier UnstructuredAddress = PKCSObjectIdentifiers_Fields.pkcs_9_at_unstructuredAddress;

		/// <summary>
		/// email address in Verisign certificates
		/// </summary>
		public static readonly ASN1ObjectIdentifier E = EmailAddress;

		/*
		* others...
		*/
		public static readonly ASN1ObjectIdentifier DC = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.25");

		/// <summary>
		/// LDAP User id.
		/// </summary>
		public static readonly ASN1ObjectIdentifier UID = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.1");

		/// <summary>
		/// default look up table translating OID values into their common symbols following
		/// the convention in RFC 2253 with a few extras
		/// </summary>
		private static readonly Hashtable DefaultSymbols = new Hashtable();

		/// <summary>
		/// look up table translating common symbols into their OIDS.
		/// </summary>
		private static readonly Hashtable DefaultLookUp = new Hashtable();

		static BCStyle()
		{
			DefaultSymbols.put(C, "C");
			DefaultSymbols.put(O, "O");
			DefaultSymbols.put(T, "T");
			DefaultSymbols.put(OU, "OU");
			DefaultSymbols.put(CN, "CN");
			DefaultSymbols.put(L, "L");
			DefaultSymbols.put(ST, "ST");
			DefaultSymbols.put(SN, "SERIALNUMBER");
			DefaultSymbols.put(EmailAddress, "E");
			DefaultSymbols.put(DC, "DC");
			DefaultSymbols.put(UID, "UID");
			DefaultSymbols.put(STREET, "STREET");
			DefaultSymbols.put(SURNAME, "SURNAME");
			DefaultSymbols.put(GIVENNAME, "GIVENNAME");
			DefaultSymbols.put(INITIALS, "INITIALS");
			DefaultSymbols.put(GENERATION, "GENERATION");
			DefaultSymbols.put(UnstructuredAddress, "unstructuredAddress");
			DefaultSymbols.put(UnstructuredName, "unstructuredName");
			DefaultSymbols.put(UNIQUE_IDENTIFIER, "UniqueIdentifier");
			DefaultSymbols.put(DN_QUALIFIER, "DN");
			DefaultSymbols.put(PSEUDONYM, "Pseudonym");
			DefaultSymbols.put(POSTAL_ADDRESS, "PostalAddress");
			DefaultSymbols.put(NAME_AT_BIRTH, "NameAtBirth");
			DefaultSymbols.put(COUNTRY_OF_CITIZENSHIP, "CountryOfCitizenship");
			DefaultSymbols.put(COUNTRY_OF_RESIDENCE, "CountryOfResidence");
			DefaultSymbols.put(GENDER, "Gender");
			DefaultSymbols.put(PLACE_OF_BIRTH, "PlaceOfBirth");
			DefaultSymbols.put(DATE_OF_BIRTH, "DateOfBirth");
			DefaultSymbols.put(POSTAL_CODE, "PostalCode");
			DefaultSymbols.put(BUSINESS_CATEGORY, "BusinessCategory");
			DefaultSymbols.put(TELEPHONE_NUMBER, "TelephoneNumber");
			DefaultSymbols.put(NAME, "Name");
			DefaultSymbols.put(ORGANIZATION_IDENTIFIER, "organizationIdentifier");

			DefaultLookUp.put("c", C);
			DefaultLookUp.put("o", O);
			DefaultLookUp.put("t", T);
			DefaultLookUp.put("ou", OU);
			DefaultLookUp.put("cn", CN);
			DefaultLookUp.put("l", L);
			DefaultLookUp.put("st", ST);
			DefaultLookUp.put("sn", SN);
			DefaultLookUp.put("serialnumber", SN);
			DefaultLookUp.put("street", STREET);
			DefaultLookUp.put("emailaddress", E);
			DefaultLookUp.put("dc", DC);
			DefaultLookUp.put("e", E);
			DefaultLookUp.put("uid", UID);
			DefaultLookUp.put("surname", SURNAME);
			DefaultLookUp.put("givenname", GIVENNAME);
			DefaultLookUp.put("initials", INITIALS);
			DefaultLookUp.put("generation", GENERATION);
			DefaultLookUp.put("unstructuredaddress", UnstructuredAddress);
			DefaultLookUp.put("unstructuredname", UnstructuredName);
			DefaultLookUp.put("uniqueidentifier", UNIQUE_IDENTIFIER);
			DefaultLookUp.put("dn", DN_QUALIFIER);
			DefaultLookUp.put("pseudonym", PSEUDONYM);
			DefaultLookUp.put("postaladdress", POSTAL_ADDRESS);
			DefaultLookUp.put("nameofbirth", NAME_AT_BIRTH);
			DefaultLookUp.put("countryofcitizenship", COUNTRY_OF_CITIZENSHIP);
			DefaultLookUp.put("countryofresidence", COUNTRY_OF_RESIDENCE);
			DefaultLookUp.put("gender", GENDER);
			DefaultLookUp.put("placeofbirth", PLACE_OF_BIRTH);
			DefaultLookUp.put("dateofbirth", DATE_OF_BIRTH);
			DefaultLookUp.put("postalcode", POSTAL_CODE);
			DefaultLookUp.put("businesscategory", BUSINESS_CATEGORY);
			DefaultLookUp.put("telephonenumber", TELEPHONE_NUMBER);
			DefaultLookUp.put("name", NAME);
			DefaultLookUp.put("organizationidentifier", ORGANIZATION_IDENTIFIER);
		}

		/// <summary>
		/// Singleton instance.
		/// </summary>
		public static readonly X500NameStyle INSTANCE = new BCStyle();

		protected internal readonly Hashtable defaultLookUp;
		protected internal readonly Hashtable defaultSymbols;

		public BCStyle()
		{
			defaultSymbols = copyHashTable(DefaultSymbols);
			defaultLookUp = copyHashTable(DefaultLookUp);
		}

		public override ASN1Encodable encodeStringValue(ASN1ObjectIdentifier oid, string value)
		{
			if (oid.Equals(EmailAddress) || oid.Equals(DC))
			{
				return new DERIA5String(value);
			}
			else if (oid.Equals(DATE_OF_BIRTH)) // accept time string as well as # (for compatibility)
			{
				return new ASN1GeneralizedTime(value);
			}
			else if (oid.Equals(C) || oid.Equals(SN) || oid.Equals(DN_QUALIFIER) || oid.Equals(TELEPHONE_NUMBER))
			{
				return new DERPrintableString(value);
			}

			return base.encodeStringValue(oid, value);
		}

		public override string oidToDisplayName(ASN1ObjectIdentifier oid)
		{
			return (string)DefaultSymbols.get(oid);
		}

		public override string[] oidToAttrNames(ASN1ObjectIdentifier oid)
		{
			return IETFUtils.findAttrNamesForOID(oid, defaultLookUp);
		}

		public override ASN1ObjectIdentifier attrNameToOID(string attrName)
		{
			return IETFUtils.decodeAttrName(attrName, defaultLookUp);
		}

		public override RDN[] fromString(string dirName)
		{
			return IETFUtils.rDNsFromString(dirName, this);
		}

		public override string ToString(X500Name name)
		{
			StringBuffer buf = new StringBuffer();
			bool first = true;

			RDN[] rdns = name.getRDNs();

			for (int i = 0; i < rdns.Length; i++)
			{
				if (first)
				{
					first = false;
				}
				else
				{
					buf.append(',');
				}

				IETFUtils.appendRDN(buf, rdns[i], defaultSymbols);
			}

			return buf.ToString();
		}


	}

}