using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1;

using System;
using System.IO;
using org.bouncycastle.asn1.x500;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;
using org.bouncycastle.util.encoders;

namespace org.bouncycastle.asn1.x509
{

				
	/// <summary>
	/// <pre>
	///     RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
	/// 
	///     RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
	/// 
	///     AttributeTypeAndValue ::= SEQUENCE {
	///                                   type  OBJECT IDENTIFIER,
	///                                   value ANY }
	/// </pre> </summary>
	/// @deprecated use org.bouncycastle.asn1.x500.X500Name. 
	public class X509Name : ASN1Object
	{
		/// <summary>
		/// country code - StringType(SIZE(2)) </summary>
		/// @deprecated use a X500NameStyle 
		public static readonly ASN1ObjectIdentifier C = new ASN1ObjectIdentifier("2.5.4.6");

		/// <summary>
		/// organization - StringType(SIZE(1..64)) </summary>
		/// @deprecated use a X500NameStyle 
		public static readonly ASN1ObjectIdentifier O = new ASN1ObjectIdentifier("2.5.4.10");

		/// <summary>
		/// organizational unit name - StringType(SIZE(1..64)) </summary>
		/// @deprecated use a X500NameStyle 
		public static readonly ASN1ObjectIdentifier OU = new ASN1ObjectIdentifier("2.5.4.11");

		/// <summary>
		/// Title </summary>
		/// @deprecated use a X500NameStyle 
		public static readonly ASN1ObjectIdentifier T = new ASN1ObjectIdentifier("2.5.4.12");

		/// <summary>
		/// common name - StringType(SIZE(1..64)) </summary>
		/// @deprecated use a X500NameStyle 
		public static readonly ASN1ObjectIdentifier CN = new ASN1ObjectIdentifier("2.5.4.3");

		/// <summary>
		/// device serial number name - StringType(SIZE(1..64))
		/// </summary>
		public static readonly ASN1ObjectIdentifier SN = new ASN1ObjectIdentifier("2.5.4.5");

		/// <summary>
		/// street - StringType(SIZE(1..64))
		/// </summary>
		public static readonly ASN1ObjectIdentifier STREET = new ASN1ObjectIdentifier("2.5.4.9");

		/// <summary>
		/// device serial number name - StringType(SIZE(1..64))
		/// </summary>
		public static readonly ASN1ObjectIdentifier SERIALNUMBER = SN;

		/// <summary>
		/// locality name - StringType(SIZE(1..64))
		/// </summary>
		public static readonly ASN1ObjectIdentifier L = new ASN1ObjectIdentifier("2.5.4.7");

		/// <summary>
		/// state, or province name - StringType(SIZE(1..64))
		/// </summary>
		public static readonly ASN1ObjectIdentifier ST = new ASN1ObjectIdentifier("2.5.4.8");

		/// <summary>
		/// Naming attributes of type X520name
		/// </summary>
		public static readonly ASN1ObjectIdentifier SURNAME = new ASN1ObjectIdentifier("2.5.4.4");
		public static readonly ASN1ObjectIdentifier GIVENNAME = new ASN1ObjectIdentifier("2.5.4.42");
		public static readonly ASN1ObjectIdentifier INITIALS = new ASN1ObjectIdentifier("2.5.4.43");
		public static readonly ASN1ObjectIdentifier GENERATION = new ASN1ObjectIdentifier("2.5.4.44");
		public static readonly ASN1ObjectIdentifier UNIQUE_IDENTIFIER = new ASN1ObjectIdentifier("2.5.4.45");

		/// <summary>
		/// businessCategory - DirectoryString(SIZE(1..128)
		/// </summary>
		public static readonly ASN1ObjectIdentifier BUSINESS_CATEGORY = new ASN1ObjectIdentifier("2.5.4.15");

		/// <summary>
		/// postalCode - DirectoryString(SIZE(1..40)
		/// </summary>
		public static readonly ASN1ObjectIdentifier POSTAL_CODE = new ASN1ObjectIdentifier("2.5.4.17");

		/// <summary>
		/// dnQualifier - DirectoryString(SIZE(1..64)
		/// </summary>
		public static readonly ASN1ObjectIdentifier DN_QUALIFIER = new ASN1ObjectIdentifier("2.5.4.46");

		/// <summary>
		/// RFC 3039 Pseudonym - DirectoryString(SIZE(1..64)
		/// </summary>
		public static readonly ASN1ObjectIdentifier PSEUDONYM = new ASN1ObjectIdentifier("2.5.4.65");


		/// <summary>
		/// RFC 3039 DateOfBirth - GeneralizedTime - YYYYMMDD000000Z
		/// </summary>
		public static readonly ASN1ObjectIdentifier DATE_OF_BIRTH = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.1");

		/// <summary>
		/// RFC 3039 PlaceOfBirth - DirectoryString(SIZE(1..128)
		/// </summary>
		public static readonly ASN1ObjectIdentifier PLACE_OF_BIRTH = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.2");

		/// <summary>
		/// RFC 3039 Gender - PrintableString (SIZE(1)) -- "M", "F", "m" or "f"
		/// </summary>
		public static readonly ASN1ObjectIdentifier GENDER = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.3");

		/// <summary>
		/// RFC 3039 CountryOfCitizenship - PrintableString (SIZE (2)) -- ISO 3166
		/// codes only
		/// </summary>
		public static readonly ASN1ObjectIdentifier COUNTRY_OF_CITIZENSHIP = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.4");

		/// <summary>
		/// RFC 3039 CountryOfResidence - PrintableString (SIZE (2)) -- ISO 3166
		/// codes only
		/// </summary>
		public static readonly ASN1ObjectIdentifier COUNTRY_OF_RESIDENCE = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.5");


		/// <summary>
		/// ISIS-MTT NameAtBirth - DirectoryString(SIZE(1..64)
		/// </summary>
		public static readonly ASN1ObjectIdentifier NAME_AT_BIRTH = new ASN1ObjectIdentifier("1.3.36.8.3.14");

		/// <summary>
		/// RFC 3039 PostalAddress - SEQUENCE SIZE (1..6) OF
		/// DirectoryString(SIZE(1..30))
		/// </summary>
		public static readonly ASN1ObjectIdentifier POSTAL_ADDRESS = new ASN1ObjectIdentifier("2.5.4.16");

		/// <summary>
		/// RFC 2256 dmdName
		/// </summary>
		public static readonly ASN1ObjectIdentifier DMD_NAME = new ASN1ObjectIdentifier("2.5.4.54");

		/// <summary>
		/// id-at-telephoneNumber
		/// </summary>
		public static readonly ASN1ObjectIdentifier TELEPHONE_NUMBER = X509ObjectIdentifiers_Fields.id_at_telephoneNumber;

		/// <summary>
		/// id-at-name
		/// </summary>
		public static readonly ASN1ObjectIdentifier NAME = X509ObjectIdentifiers_Fields.id_at_name;

		/// <summary>
		/// Email address (RSA PKCS#9 extension) - IA5String.
		/// <para>Note: if you're trying to be ultra orthodox, don't use this! It shouldn't be in here.
		/// </para>
		/// </summary>
		/// @deprecated use a X500NameStyle 
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
		/// determines whether or not strings should be processed and printed
		/// from back to front.
		/// </summary>
		public static bool DefaultReverse = false;

		/// <summary>
		/// default look up table translating OID values into their common symbols following
		/// the convention in RFC 2253 with a few extras
		/// </summary>
		public static readonly Hashtable DefaultSymbols = new Hashtable();

		/// <summary>
		/// look up table translating OID values into their common symbols following the convention in RFC 2253
		/// 
		/// </summary>
		public static readonly Hashtable RFC2253Symbols = new Hashtable();

		/// <summary>
		/// look up table translating OID values into their common symbols following the convention in RFC 1779
		/// 
		/// </summary>
		public static readonly Hashtable RFC1779Symbols = new Hashtable();

		/// <summary>
		/// look up table translating common symbols into their OIDS.
		/// </summary>
		public static readonly Hashtable DefaultLookUp = new Hashtable();

		/// <summary>
		/// look up table translating OID values into their common symbols </summary>
		/// @deprecated use DefaultSymbols 
		public static readonly Hashtable OIDLookUp = DefaultSymbols;

		/// <summary>
		/// look up table translating string values into their OIDS - </summary>
		/// @deprecated use DefaultLookUp 
		public static readonly Hashtable SymbolLookUp = DefaultLookUp;

		private static readonly bool? TRUE = new bool?(true); // for J2ME compatibility
		private static readonly bool? FALSE = new bool?(false);

		static X509Name()
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

			RFC2253Symbols.put(C, "C");
			RFC2253Symbols.put(O, "O");
			RFC2253Symbols.put(OU, "OU");
			RFC2253Symbols.put(CN, "CN");
			RFC2253Symbols.put(L, "L");
			RFC2253Symbols.put(ST, "ST");
			RFC2253Symbols.put(STREET, "STREET");
			RFC2253Symbols.put(DC, "DC");
			RFC2253Symbols.put(UID, "UID");

			RFC1779Symbols.put(C, "C");
			RFC1779Symbols.put(O, "O");
			RFC1779Symbols.put(OU, "OU");
			RFC1779Symbols.put(CN, "CN");
			RFC1779Symbols.put(L, "L");
			RFC1779Symbols.put(ST, "ST");
			RFC1779Symbols.put(STREET, "STREET");

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
		}

		private X509NameEntryConverter converter = null;
		private Vector ordering = new Vector();
		private Vector values = new Vector();
		private Vector added = new Vector();

		private ASN1Sequence seq;

		private bool isHashCodeCalculated;
		private int hashCodeValue;

		/// <summary>
		/// Return a X509Name based on the passed in tagged object.
		/// </summary>
		/// <param name="obj"> tag object holding name. </param>
		/// <param name="explicit"> true if explicitly tagged false otherwise. </param>
		/// <returns> the X509Name </returns>
		public static X509Name getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static X509Name getInstance(object obj)
		{
			if (obj == null || obj is X509Name)
			{
				return (X509Name)obj;
			}
			else if (obj is X500Name)
			{
				return new X509Name(ASN1Sequence.getInstance(((X500Name)obj).toASN1Primitive()));
			}
			else if (obj != null)
			{
				return new X509Name(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public X509Name()
		{
			// constructure use by new X500 Name class
		}
		/// <summary>
		/// Constructor from ASN1Sequence
		/// 
		/// the principal will be a list of constructed sets, each containing an (OID, String) pair. </summary>
		/// @deprecated use X500Name.getInstance() 
		public X509Name(ASN1Sequence seq)
		{
			this.seq = seq;

			Enumeration e = seq.getObjects();

			while (e.hasMoreElements())
			{
				ASN1Set set = ASN1Set.getInstance(((ASN1Encodable)e.nextElement()).toASN1Primitive());

				for (int i = 0; i < set.size(); i++)
				{
					   ASN1Sequence s = ASN1Sequence.getInstance(set.getObjectAt(i).toASN1Primitive());

					   if (s.size() != 2)
					   {
						   throw new IllegalArgumentException("badly sized pair");
					   }

					   ordering.addElement(ASN1ObjectIdentifier.getInstance(s.getObjectAt(0)));

					   ASN1Encodable value = s.getObjectAt(1);
					   if (value is ASN1String && !(value is DERUniversalString))
					   {
						   string v = ((ASN1String)value).getString();
						   if (v.Length > 0 && v[0] == '#')
						   {
							   values.addElement(@"\" + v);
						   }
						   else
						   {
							   values.addElement(v);
						   }
					   }
					   else
					   {
						   try
						   {
							   values.addElement("#" + bytesToString(Hex.encode(value.toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER))));
						   }
						   catch (IOException)
						   {
							   throw new IllegalArgumentException("cannot encode value");
						   }
					   }
					   added.addElement((i != 0) ? TRUE : FALSE); // to allow earlier JDK compatibility
				}
			}
		}

		/// <summary>
		/// constructor from a table of attributes.
		/// <para>
		/// it's is assumed the table contains OID/String pairs, and the contents
		/// of the table are copied into an internal table as part of the
		/// construction process.
		/// </para>
		/// <para>
		/// <b>Note:</b> if the name you are trying to generate should be
		/// following a specific ordering, you should use the constructor
		/// with the ordering specified below.
		/// </para>
		/// </summary>
		/// @deprecated use an ordered constructor! The hashtable ordering is rarely correct 
		public X509Name(Hashtable attributes) : this(null, attributes)
		{
		}

		/// <summary>
		/// Constructor from a table of attributes with ordering.
		/// <para>
		/// it's is assumed the table contains OID/String pairs, and the contents
		/// of the table are copied into an internal table as part of the
		/// construction process. The ordering vector should contain the OIDs
		/// in the order they are meant to be encoded or printed in toString.
		/// </para>
		/// </summary>
		public X509Name(Vector ordering, Hashtable attributes) : this(ordering, attributes, new X509DefaultEntryConverter())
		{
		}

		/// <summary>
		/// Constructor from a table of attributes with ordering.
		/// <para>
		/// it's is assumed the table contains OID/String pairs, and the contents
		/// of the table are copied into an internal table as part of the
		/// construction process. The ordering vector should contain the OIDs
		/// in the order they are meant to be encoded or printed in toString.
		/// </para>
		/// <para>
		/// The passed in converter will be used to convert the strings into their
		/// ASN.1 counterparts.
		/// </para>
		/// </summary>
		/// @deprecated use X500Name, X500NameBuilder 
		public X509Name(Vector ordering, Hashtable attributes, X509NameEntryConverter converter)
		{
			this.converter = converter;

			if (ordering != null)
			{
				for (int i = 0; i != ordering.size(); i++)
				{
					this.ordering.addElement(ordering.elementAt(i));
					this.added.addElement(FALSE);
				}
			}
			else
			{
				Enumeration e = attributes.keys();

				while (e.hasMoreElements())
				{
					this.ordering.addElement(e.nextElement());
					this.added.addElement(FALSE);
				}
			}

			for (int i = 0; i != this.ordering.size(); i++)
			{
				ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)this.ordering.elementAt(i);

				if (attributes.get(oid) == null)
				{
					throw new IllegalArgumentException("No attribute for object id - " + oid.getId() + " - passed to distinguished name");
				}

				this.values.addElement(attributes.get(oid)); // copy the hash table
			}
		}

		/// <summary>
		/// Takes two vectors one of the oids and the other of the values. </summary>
		/// @deprecated use X500Name, X500NameBuilder 
		public X509Name(Vector oids, Vector values) : this(oids, values, new X509DefaultEntryConverter())
		{
		}

		/// <summary>
		/// Takes two vectors one of the oids and the other of the values.
		/// <para>
		/// The passed in converter will be used to convert the strings into their
		/// ASN.1 counterparts.
		/// </para>
		/// </summary>
		/// @deprecated use X500Name, X500NameBuilder 
		public X509Name(Vector oids, Vector values, X509NameEntryConverter converter)
		{
			this.converter = converter;

			if (oids.size() != values.size())
			{
				throw new IllegalArgumentException("oids vector must be same length as values.");
			}

			for (int i = 0; i < oids.size(); i++)
			{
				this.ordering.addElement(oids.elementAt(i));
				this.values.addElement(values.elementAt(i));
				this.added.addElement(FALSE);
			}
		}

	//    private Boolean isEncoded(String s)
	//    {
	//        if (s.charAt(0) == '#')
	//        {
	//            return TRUE;
	//        }
	//
	//        return FALSE;
	//    }

		/// <summary>
		/// Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
		/// some such, converting it into an ordered set of name attributes. </summary>
		/// @deprecated use X500Name, X500NameBuilder 
		public X509Name(string dirName) : this(DefaultReverse, DefaultLookUp, dirName)
		{
		}

		/// <summary>
		/// Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
		/// some such, converting it into an ordered set of name attributes with each
		/// string value being converted to its associated ASN.1 type using the passed
		/// in converter. </summary>
		/// @deprecated use X500Name, X500NameBuilder 
		public X509Name(string dirName, X509NameEntryConverter converter) : this(DefaultReverse, DefaultLookUp, dirName, converter)
		{
		}

		/// <summary>
		/// Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
		/// some such, converting it into an ordered set of name attributes. If reverse
		/// is true, create the encoded version of the sequence starting from the
		/// last element in the string. </summary>
		/// @deprecated use X500Name, X500NameBuilder 
		public X509Name(bool reverse, string dirName) : this(reverse, DefaultLookUp, dirName)
		{
		}

		/// <summary>
		/// Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
		/// some such, converting it into an ordered set of name attributes with each
		/// string value being converted to its associated ASN.1 type using the passed
		/// in converter. If reverse is true the ASN.1 sequence representing the DN will
		/// be built by starting at the end of the string, rather than the start. </summary>
		/// @deprecated use X500Name, X500NameBuilder 
		public X509Name(bool reverse, string dirName, X509NameEntryConverter converter) : this(reverse, DefaultLookUp, dirName, converter)
		{
		}

		/// <summary>
		/// Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
		/// some such, converting it into an ordered set of name attributes. lookUp
		/// should provide a table of lookups, indexed by lowercase only strings and
		/// yielding a ASN1ObjectIdentifier, other than that OID. and numeric oids
		/// will be processed automatically.
		/// <br>
		/// If reverse is true, create the encoded version of the sequence
		/// starting from the last element in the string. </summary>
		/// <param name="reverse"> true if we should start scanning from the end (RFC 2553). </param>
		/// <param name="lookUp"> table of names and their oids. </param>
		/// <param name="dirName"> the X.500 string to be parsed. </param>
		/// @deprecated use X500Name, X500NameBuilder 
		public X509Name(bool reverse, Hashtable lookUp, string dirName) : this(reverse, lookUp, dirName, new X509DefaultEntryConverter())
		{
		}

		private ASN1ObjectIdentifier decodeOID(string name, Hashtable lookUp)
		{
			name = name.Trim();
			if (Strings.toUpperCase(name).StartsWith("OID.", StringComparison.Ordinal))
			{
				return new ASN1ObjectIdentifier(name.Substring(4));
			}
			else if (name[0] >= '0' && name[0] <= '9')
			{
				return new ASN1ObjectIdentifier(name);
			}

			ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)lookUp.get(Strings.toLowerCase(name));
			if (oid == null)
			{
				throw new IllegalArgumentException("Unknown object id - " + name + " - passed to distinguished name");
			}

			return oid;
		}

		private string unescape(string elt)
		{
			if (elt.Length == 0 || (elt.IndexOf('\\') < 0 && elt.IndexOf('"') < 0))
			{
				return elt.Trim();
			}

			char[] elts = elt.ToCharArray();
			bool escaped = false;
			bool quoted = false;
			StringBuffer buf = new StringBuffer(elt.Length);
			int start = 0;

			// if it's an escaped hash string and not an actual encoding in string form
			// we need to leave it escaped.
			if (elts[0] == '\\')
			{
				if (elts[1] == '#')
				{
					start = 2;
					buf.append(@"\#");
				}
			}

			bool nonWhiteSpaceEncountered = false;
			int lastEscaped = 0;

			for (int i = start; i != elts.Length; i++)
			{
				char c = elts[i];

				if (c != ' ')
				{
					nonWhiteSpaceEncountered = true;
				}

				if (c == '"')
				{
					if (!escaped)
					{
						quoted = !quoted;
					}
					else
					{
						buf.append(c);
					}
					escaped = false;
				}
				else if (c == '\\' && !(escaped || quoted))
				{
					escaped = true;
					lastEscaped = buf.length();
				}
				else
				{
					if (c == ' ' && !escaped && !nonWhiteSpaceEncountered)
					{
						continue;
					}
					buf.append(c);
					escaped = false;
				}
			}

			if (buf.length() > 0)
			{
				while (buf.charAt(buf.length() - 1) == ' ' && lastEscaped != (buf.length() - 1))
				{
					buf.setLength(buf.length() - 1);
				}
			}

			return buf.ToString();
		}

		/// <summary>
		/// Takes an X509 dir name as a string of the format "C=AU, ST=Victoria", or
		/// some such, converting it into an ordered set of name attributes. lookUp
		/// should provide a table of lookups, indexed by lowercase only strings and
		/// yielding a ASN1ObjectIdentifier, other than that OID. and numeric oids
		/// will be processed automatically. The passed in converter is used to convert the
		/// string values to the right of each equals sign to their ASN.1 counterparts.
		/// <br> </summary>
		/// <param name="reverse"> true if we should start scanning from the end, false otherwise. </param>
		/// <param name="lookUp"> table of names and oids. </param>
		/// <param name="dirName"> the string dirName </param>
		/// <param name="converter"> the converter to convert string values into their ASN.1 equivalents </param>
		public X509Name(bool reverse, Hashtable lookUp, string dirName, X509NameEntryConverter converter)
		{
			this.converter = converter;
			X509NameTokenizer nTok = new X509NameTokenizer(dirName);

			while (nTok.hasMoreTokens())
			{
				string token = nTok.nextToken();

				if (token.IndexOf('+') > 0)
				{
					X509NameTokenizer pTok = new X509NameTokenizer(token, '+');

					addEntry(lookUp, pTok.nextToken(), FALSE);

					while (pTok.hasMoreTokens())
					{
						addEntry(lookUp, pTok.nextToken(), TRUE);
					}
				}
				else
				{
					addEntry(lookUp, token, FALSE);
				}
			}

			if (reverse)
			{
				Vector o = new Vector();
				Vector v = new Vector();
				Vector a = new Vector();

				int count = 1;

				for (int i = 0; i < this.ordering.size(); i++)
				{
					if (((bool?)this.added.elementAt(i)).Value)
					{
						o.insertElementAt(this.ordering.elementAt(i), count);
						v.insertElementAt(this.values.elementAt(i), count);
						a.insertElementAt(this.added.elementAt(i), count);
						count++;
					}
					else
					{
						o.insertElementAt(this.ordering.elementAt(i), 0);
						v.insertElementAt(this.values.elementAt(i), 0);
						a.insertElementAt(this.added.elementAt(i), 0);
						count = 1;
					}
				}

				this.ordering = o;
				this.values = v;
				this.added = a;
			}
		}

		private void addEntry(Hashtable lookUp, string token, bool? isAdded)
		{
			X509NameTokenizer vTok;
			string name;
			string value;
			ASN1ObjectIdentifier oid;
			vTok = new X509NameTokenizer(token, '=');

			name = vTok.nextToken();

			if (!vTok.hasMoreTokens())
			{
			   throw new IllegalArgumentException("badly formatted directory string");
			}

			value = vTok.nextToken();

			oid = decodeOID(name, lookUp);

			this.ordering.addElement(oid);
			this.values.addElement(unescape(value));
			this.added.addElement(isAdded);
		}

		/// <summary>
		/// return a vector of the oids in the name, in the order they were found.
		/// </summary>
		public virtual Vector getOIDs()
		{
			Vector v = new Vector();

			for (int i = 0; i != ordering.size(); i++)
			{
				v.addElement(ordering.elementAt(i));
			}

			return v;
		}

		/// <summary>
		/// return a vector of the values found in the name, in the order they
		/// were found.
		/// </summary>
		public virtual Vector getValues()
		{
			Vector v = new Vector();

			for (int i = 0; i != values.size(); i++)
			{
				v.addElement(values.elementAt(i));
			}

			return v;
		}

		/// <summary>
		/// return a vector of the values found in the name, in the order they
		/// were found, with the DN label corresponding to passed in oid.
		/// </summary>
		public virtual Vector getValues(ASN1ObjectIdentifier oid)
		{
			Vector v = new Vector();

			for (int i = 0; i != values.size(); i++)
			{
				if (ordering.elementAt(i).Equals(oid))
				{
					string val = (string)values.elementAt(i);

					if (val.Length > 2 && val[0] == '\\' && val[1] == '#')
					{
						v.addElement(val.Substring(1));
					}
					else
					{
						v.addElement(val);
					}
				}
			}

			return v;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			if (seq == null)
			{
				ASN1EncodableVector vec = new ASN1EncodableVector();
				ASN1EncodableVector sVec = new ASN1EncodableVector();
				ASN1ObjectIdentifier lstOid = null;

				for (int i = 0; i != ordering.size(); i++)
				{
					ASN1EncodableVector v = new ASN1EncodableVector();
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)ordering.elementAt(i);

					v.add(oid);

					string str = (string)values.elementAt(i);

					v.add(converter.getConvertedValue(oid, str));

					if (lstOid == null || ((bool?)this.added.elementAt(i)).Value)
					{
						sVec.add(new DERSequence(v));
					}
					else
					{
						vec.add(new DERSet(sVec));
						sVec = new ASN1EncodableVector();

						sVec.add(new DERSequence(v));
					}

					lstOid = oid;
				}

				vec.add(new DERSet(sVec));

				seq = new DERSequence(vec);
			}

			return seq;
		}

		/// <param name="inOrder"> if true the order of both X509 names must be the same,
		/// as well as the values associated with each element. </param>
		public virtual bool Equals(object obj, bool inOrder)
		{
			if (!inOrder)
			{
				return this.Equals(obj);
			}

			if (obj == this)
			{
				return true;
			}

			if (!(obj is X509Name || obj is ASN1Sequence))
			{
				return false;
			}

			ASN1Primitive derO = ((ASN1Encodable)obj).toASN1Primitive();

			if (this.toASN1Primitive().Equals(derO))
			{
				return true;
			}

			X509Name other;

			try
			{
				other = X509Name.getInstance(obj);
			}
			catch (IllegalArgumentException)
			{
				return false;
			}

			int orderingSize = ordering.size();

			if (orderingSize != other.ordering.size())
			{
				return false;
			}

			for (int i = 0; i < orderingSize; i++)
			{
				ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)ordering.elementAt(i);
				ASN1ObjectIdentifier oOid = (ASN1ObjectIdentifier)other.ordering.elementAt(i);

				if (oid.Equals(oOid))
				{
					string value = (string)values.elementAt(i);
					string oValue = (string)other.values.elementAt(i);

					if (!equivalentStrings(value, oValue))
					{
						return false;
					}
				}
				else
				{
					return false;
				}
			}

			return true;
		}

		public override int GetHashCode()
		{
			if (isHashCodeCalculated)
			{
				return hashCodeValue;
			}

			isHashCodeCalculated = true;

			// this needs to be order independent, like equals
			for (int i = 0; i != ordering.size(); i += 1)
			{
				string value = (string)values.elementAt(i);

				value = canonicalize(value);
				value = stripInternalSpaces(value);

				hashCodeValue ^= ordering.elementAt(i).GetHashCode();
				hashCodeValue ^= value.GetHashCode();
			}

			return hashCodeValue;
		}

		/// <summary>
		/// test for equality - note: case is ignored.
		/// </summary>
		public override bool Equals(object obj)
		{
			if (obj == this)
			{
				return true;
			}

			if (!(obj is X509Name || obj is ASN1Sequence))
			{
				return false;
			}

			ASN1Primitive derO = ((ASN1Encodable)obj).toASN1Primitive();

			if (this.toASN1Primitive().Equals(derO))
			{
				return true;
			}

			X509Name other;

			try
			{
				other = X509Name.getInstance(obj);
			}
			catch (IllegalArgumentException)
			{
				return false;
			}

			int orderingSize = ordering.size();

			if (orderingSize != other.ordering.size())
			{
				return false;
			}

			bool[] indexes = new bool[orderingSize];
			int start, end, delta;

			if (ordering.elementAt(0).Equals(other.ordering.elementAt(0))) // guess forward
			{
				start = 0;
				end = orderingSize;
				delta = 1;
			}
			else // guess reversed - most common problem
			{
				start = orderingSize - 1;
				end = -1;
				delta = -1;
			}

			for (int i = start; i != end; i += delta)
			{
				bool found = false;
				ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)ordering.elementAt(i);
				string value = (string)values.elementAt(i);

				for (int j = 0; j < orderingSize; j++)
				{
					if (indexes[j])
					{
						continue;
					}

					ASN1ObjectIdentifier oOid = (ASN1ObjectIdentifier)other.ordering.elementAt(j);

					if (oid.Equals(oOid))
					{
						string oValue = (string)other.values.elementAt(j);

						if (equivalentStrings(value, oValue))
						{
							indexes[j] = true;
							found = true;
							break;
						}
					}
				}

				if (!found)
				{
					return false;
				}
			}

			return true;
		}

		private bool equivalentStrings(string s1, string s2)
		{
			string value = canonicalize(s1);
			string oValue = canonicalize(s2);

			if (!value.Equals(oValue))
			{
				value = stripInternalSpaces(value);
				oValue = stripInternalSpaces(oValue);

				if (!value.Equals(oValue))
				{
					return false;
				}
			}

			return true;
		}

		private string canonicalize(string s)
		{
			string value = Strings.toLowerCase(s.Trim());

			if (value.Length > 0 && value[0] == '#')
			{
				ASN1Primitive obj = decodeObject(value);

				if (obj is ASN1String)
				{
					value = Strings.toLowerCase(((ASN1String)obj).getString().Trim());
				}
			}

			return value;
		}

		private ASN1Primitive decodeObject(string oValue)
		{
			try
			{
				return ASN1Primitive.fromByteArray(Hex.decode(oValue.Substring(1)));
			}
			catch (IOException e)
			{
				throw new IllegalStateException("unknown encoding in name: " + e);
			}
		}

		private string stripInternalSpaces(string str)
		{
			StringBuffer res = new StringBuffer();

			if (str.Length != 0)
			{
				char c1 = str[0];

				res.append(c1);

				for (int k = 1; k < str.Length; k++)
				{
					char c2 = str[k];
					if (!(c1 == ' ' && c2 == ' '))
					{
						res.append(c2);
					}
					c1 = c2;
				}
			}

			return res.ToString();
		}

		private void appendValue(StringBuffer buf, Hashtable oidSymbols, ASN1ObjectIdentifier oid, string value)
		{
			string sym = (string)oidSymbols.get(oid);

			if (!string.ReferenceEquals(sym, null))
			{
				buf.append(sym);
			}
			else
			{
				buf.append(oid.getId());
			}

			buf.append('=');

			int start = buf.length();
			buf.append(value);
			int end = buf.length();

			if (value.Length >= 2 && value[0] == '\\' && value[1] == '#')
			{
				start += 2;
			}

			while (start < end && buf.charAt(start) == ' ')
			{
				buf.insert(start, @"\");
				start += 2;
				++end;
			}

			while (--end > start && buf.charAt(end) == ' ')
			{
				buf.insert(end, '\\');
			}

			while (start <= end)
			{
				switch (buf.charAt(start))
				{
				case ',':
				case '"':
				case '\\':
				case '+':
				case '=':
				case '<':
				case '>':
				case ';':
					buf.insert(start, @"\");
					start += 2;
					++end;
					break;
				default:
					++start;
					break;
				}
			}
		}

		/// <summary>
		/// convert the structure to a string - if reverse is true the
		/// oids and values are listed out starting with the last element
		/// in the sequence (ala RFC 2253), otherwise the string will begin
		/// with the first element of the structure. If no string definition
		/// for the oid is found in oidSymbols the string value of the oid is
		/// added. Two standard symbol tables are provided DefaultSymbols, and
		/// RFC2253Symbols as part of this class.
		/// </summary>
		/// <param name="reverse"> if true start at the end of the sequence and work back. </param>
		/// <param name="oidSymbols"> look up table strings for oids. </param>
		public virtual string ToString(bool reverse, Hashtable oidSymbols)
		{
			StringBuffer buf = new StringBuffer();
			Vector components = new Vector();
			bool first = true;

			StringBuffer ava = null;

			for (int i = 0; i < ordering.size(); i++)
			{
				if (((bool?)added.elementAt(i)).Value)
				{
					ava.append('+');
					appendValue(ava, oidSymbols, (ASN1ObjectIdentifier)ordering.elementAt(i), (string)values.elementAt(i));
				}
				else
				{
					ava = new StringBuffer();
					appendValue(ava, oidSymbols, (ASN1ObjectIdentifier)ordering.elementAt(i), (string)values.elementAt(i));
					components.addElement(ava);
				}
			}

			if (reverse)
			{
				for (int i = components.size() - 1; i >= 0; i--)
				{
					if (first)
					{
						first = false;
					}
					else
					{
						buf.append(',');
					}

					buf.append(components.elementAt(i).ToString());
				}
			}
			else
			{
				for (int i = 0; i < components.size(); i++)
				{
					if (first)
					{
						first = false;
					}
					else
					{
						buf.append(',');
					}

					buf.append(components.elementAt(i).ToString());
				}
			}

			return buf.ToString();
		}

		private string bytesToString(byte[] data)
		{
			char[] cs = new char[data.Length];

			for (int i = 0; i != cs.Length; i++)
			{
				cs[i] = (char)(data[i] & 0xff);
			}

			return new string(cs);
		}

		public override string ToString()
		{
			return ToString(DefaultReverse, DefaultSymbols);
		}
	}

}