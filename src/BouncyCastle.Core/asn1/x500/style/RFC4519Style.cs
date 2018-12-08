using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x500.style
{


	public class RFC4519Style : AbstractX500NameStyle
	{
		public static readonly ASN1ObjectIdentifier businessCategory = new ASN1ObjectIdentifier("2.5.4.15").intern();
		public static readonly ASN1ObjectIdentifier c = new ASN1ObjectIdentifier("2.5.4.6").intern();
		public static readonly ASN1ObjectIdentifier cn = new ASN1ObjectIdentifier("2.5.4.3").intern();
		public static readonly ASN1ObjectIdentifier dc = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.25").intern();
		public static readonly ASN1ObjectIdentifier description = new ASN1ObjectIdentifier("2.5.4.13").intern();
		public static readonly ASN1ObjectIdentifier destinationIndicator = new ASN1ObjectIdentifier("2.5.4.27").intern();
		public static readonly ASN1ObjectIdentifier distinguishedName = new ASN1ObjectIdentifier("2.5.4.49").intern();
		public static readonly ASN1ObjectIdentifier dnQualifier = new ASN1ObjectIdentifier("2.5.4.46").intern();
		public static readonly ASN1ObjectIdentifier enhancedSearchGuide = new ASN1ObjectIdentifier("2.5.4.47").intern();
		public static readonly ASN1ObjectIdentifier facsimileTelephoneNumber = new ASN1ObjectIdentifier("2.5.4.23").intern();
		public static readonly ASN1ObjectIdentifier generationQualifier = new ASN1ObjectIdentifier("2.5.4.44").intern();
		public static readonly ASN1ObjectIdentifier givenName = new ASN1ObjectIdentifier("2.5.4.42").intern();
		public static readonly ASN1ObjectIdentifier houseIdentifier = new ASN1ObjectIdentifier("2.5.4.51").intern();
		public static readonly ASN1ObjectIdentifier initials = new ASN1ObjectIdentifier("2.5.4.43").intern();
		public static readonly ASN1ObjectIdentifier internationalISDNNumber = new ASN1ObjectIdentifier("2.5.4.25").intern();
		public static readonly ASN1ObjectIdentifier l = new ASN1ObjectIdentifier("2.5.4.7").intern();
		public static readonly ASN1ObjectIdentifier member = new ASN1ObjectIdentifier("2.5.4.31").intern();
		public static readonly ASN1ObjectIdentifier name = new ASN1ObjectIdentifier("2.5.4.41").intern();
		public static readonly ASN1ObjectIdentifier o = new ASN1ObjectIdentifier("2.5.4.10").intern();
		public static readonly ASN1ObjectIdentifier ou = new ASN1ObjectIdentifier("2.5.4.11").intern();
		public static readonly ASN1ObjectIdentifier owner = new ASN1ObjectIdentifier("2.5.4.32").intern();
		public static readonly ASN1ObjectIdentifier physicalDeliveryOfficeName = new ASN1ObjectIdentifier("2.5.4.19").intern();
		public static readonly ASN1ObjectIdentifier postalAddress = new ASN1ObjectIdentifier("2.5.4.16").intern();
		public static readonly ASN1ObjectIdentifier postalCode = new ASN1ObjectIdentifier("2.5.4.17").intern();
		public static readonly ASN1ObjectIdentifier postOfficeBox = new ASN1ObjectIdentifier("2.5.4.18").intern();
		public static readonly ASN1ObjectIdentifier preferredDeliveryMethod = new ASN1ObjectIdentifier("2.5.4.28").intern();
		public static readonly ASN1ObjectIdentifier registeredAddress = new ASN1ObjectIdentifier("2.5.4.26").intern();
		public static readonly ASN1ObjectIdentifier roleOccupant = new ASN1ObjectIdentifier("2.5.4.33").intern();
		public static readonly ASN1ObjectIdentifier searchGuide = new ASN1ObjectIdentifier("2.5.4.14").intern();
		public static readonly ASN1ObjectIdentifier seeAlso = new ASN1ObjectIdentifier("2.5.4.34").intern();
		public static readonly ASN1ObjectIdentifier serialNumber = new ASN1ObjectIdentifier("2.5.4.5").intern();
		public static readonly ASN1ObjectIdentifier sn = new ASN1ObjectIdentifier("2.5.4.4").intern();
		public static readonly ASN1ObjectIdentifier st = new ASN1ObjectIdentifier("2.5.4.8").intern();
		public static readonly ASN1ObjectIdentifier street = new ASN1ObjectIdentifier("2.5.4.9").intern();
		public static readonly ASN1ObjectIdentifier telephoneNumber = new ASN1ObjectIdentifier("2.5.4.20").intern();
		public static readonly ASN1ObjectIdentifier teletexTerminalIdentifier = new ASN1ObjectIdentifier("2.5.4.22").intern();
		public static readonly ASN1ObjectIdentifier telexNumber = new ASN1ObjectIdentifier("2.5.4.21").intern();
		public static readonly ASN1ObjectIdentifier title = new ASN1ObjectIdentifier("2.5.4.12").intern();
		public static readonly ASN1ObjectIdentifier uid = new ASN1ObjectIdentifier("0.9.2342.19200300.100.1.1").intern();
		public static readonly ASN1ObjectIdentifier uniqueMember = new ASN1ObjectIdentifier("2.5.4.50").intern();
		public static readonly ASN1ObjectIdentifier userPassword = new ASN1ObjectIdentifier("2.5.4.35").intern();
		public static readonly ASN1ObjectIdentifier x121Address = new ASN1ObjectIdentifier("2.5.4.24").intern();
		public static readonly ASN1ObjectIdentifier x500UniqueIdentifier = new ASN1ObjectIdentifier("2.5.4.45").intern();

		/// <summary>
		/// default look up table translating OID values into their common symbols following
		/// the convention in RFC 2253 with a few extras
		/// </summary>
		private static readonly Hashtable DefaultSymbols = new Hashtable();

		/// <summary>
		/// look up table translating common symbols into their OIDS.
		/// </summary>
		private static readonly Hashtable DefaultLookUp = new Hashtable();

		static RFC4519Style()
		{
			DefaultSymbols.put(businessCategory, "businessCategory");
			DefaultSymbols.put(c, "c");
			DefaultSymbols.put(cn, "cn");
			DefaultSymbols.put(dc, "dc");
			DefaultSymbols.put(description, "description");
			DefaultSymbols.put(destinationIndicator, "destinationIndicator");
			DefaultSymbols.put(distinguishedName, "distinguishedName");
			DefaultSymbols.put(dnQualifier, "dnQualifier");
			DefaultSymbols.put(enhancedSearchGuide, "enhancedSearchGuide");
			DefaultSymbols.put(facsimileTelephoneNumber, "facsimileTelephoneNumber");
			DefaultSymbols.put(generationQualifier, "generationQualifier");
			DefaultSymbols.put(givenName, "givenName");
			DefaultSymbols.put(houseIdentifier, "houseIdentifier");
			DefaultSymbols.put(initials, "initials");
			DefaultSymbols.put(internationalISDNNumber, "internationalISDNNumber");
			DefaultSymbols.put(l, "l");
			DefaultSymbols.put(member, "member");
			DefaultSymbols.put(name, "name");
			DefaultSymbols.put(o, "o");
			DefaultSymbols.put(ou, "ou");
			DefaultSymbols.put(owner, "owner");
			DefaultSymbols.put(physicalDeliveryOfficeName, "physicalDeliveryOfficeName");
			DefaultSymbols.put(postalAddress, "postalAddress");
			DefaultSymbols.put(postalCode, "postalCode");
			DefaultSymbols.put(postOfficeBox, "postOfficeBox");
			DefaultSymbols.put(preferredDeliveryMethod, "preferredDeliveryMethod");
			DefaultSymbols.put(registeredAddress, "registeredAddress");
			DefaultSymbols.put(roleOccupant, "roleOccupant");
			DefaultSymbols.put(searchGuide, "searchGuide");
			DefaultSymbols.put(seeAlso, "seeAlso");
			DefaultSymbols.put(serialNumber, "serialNumber");
			DefaultSymbols.put(sn, "sn");
			DefaultSymbols.put(st, "st");
			DefaultSymbols.put(street, "street");
			DefaultSymbols.put(telephoneNumber, "telephoneNumber");
			DefaultSymbols.put(teletexTerminalIdentifier, "teletexTerminalIdentifier");
			DefaultSymbols.put(telexNumber, "telexNumber");
			DefaultSymbols.put(title, "title");
			DefaultSymbols.put(uid, "uid");
			DefaultSymbols.put(uniqueMember, "uniqueMember");
			DefaultSymbols.put(userPassword, "userPassword");
			DefaultSymbols.put(x121Address, "x121Address");
			DefaultSymbols.put(x500UniqueIdentifier, "x500UniqueIdentifier");

			DefaultLookUp.put("businesscategory", businessCategory);
			DefaultLookUp.put("c", c);
			DefaultLookUp.put("cn", cn);
			DefaultLookUp.put("dc", dc);
			DefaultLookUp.put("description", description);
			DefaultLookUp.put("destinationindicator", destinationIndicator);
			DefaultLookUp.put("distinguishedname", distinguishedName);
			DefaultLookUp.put("dnqualifier", dnQualifier);
			DefaultLookUp.put("enhancedsearchguide", enhancedSearchGuide);
			DefaultLookUp.put("facsimiletelephonenumber", facsimileTelephoneNumber);
			DefaultLookUp.put("generationqualifier", generationQualifier);
			DefaultLookUp.put("givenname", givenName);
			DefaultLookUp.put("houseidentifier", houseIdentifier);
			DefaultLookUp.put("initials", initials);
			DefaultLookUp.put("internationalisdnnumber", internationalISDNNumber);
			DefaultLookUp.put("l", l);
			DefaultLookUp.put("member", member);
			DefaultLookUp.put("name", name);
			DefaultLookUp.put("o", o);
			DefaultLookUp.put("ou", ou);
			DefaultLookUp.put("owner", owner);
			DefaultLookUp.put("physicaldeliveryofficename", physicalDeliveryOfficeName);
			DefaultLookUp.put("postaladdress", postalAddress);
			DefaultLookUp.put("postalcode", postalCode);
			DefaultLookUp.put("postofficebox", postOfficeBox);
			DefaultLookUp.put("preferreddeliverymethod", preferredDeliveryMethod);
			DefaultLookUp.put("registeredaddress", registeredAddress);
			DefaultLookUp.put("roleoccupant", roleOccupant);
			DefaultLookUp.put("searchguide", searchGuide);
			DefaultLookUp.put("seealso", seeAlso);
			DefaultLookUp.put("serialnumber", serialNumber);
			DefaultLookUp.put("sn", sn);
			DefaultLookUp.put("st", st);
			DefaultLookUp.put("street", street);
			DefaultLookUp.put("telephonenumber", telephoneNumber);
			DefaultLookUp.put("teletexterminalidentifier", teletexTerminalIdentifier);
			DefaultLookUp.put("telexnumber", telexNumber);
			DefaultLookUp.put("title", title);
			DefaultLookUp.put("uid", uid);
			DefaultLookUp.put("uniquemember", uniqueMember);
			DefaultLookUp.put("userpassword", userPassword);
			DefaultLookUp.put("x121address", x121Address);
			DefaultLookUp.put("x500uniqueidentifier", x500UniqueIdentifier);

			// TODO: need to add correct matching for equality comparisons.
		}

		/// <summary>
		/// Singleton instance.
		/// </summary>
		public static readonly X500NameStyle INSTANCE = new RFC4519Style();

		protected internal readonly Hashtable defaultLookUp;
		protected internal readonly Hashtable defaultSymbols;

		public RFC4519Style()
		{
			defaultSymbols = copyHashTable(DefaultSymbols);
			defaultLookUp = copyHashTable(DefaultLookUp);
		}

		public override ASN1Encodable encodeStringValue(ASN1ObjectIdentifier oid, string value)
		{
			if (oid.Equals(dc))
			{
				return new DERIA5String(value);
			}
			else if (oid.Equals(c) || oid.Equals(serialNumber) || oid.Equals(dnQualifier) || oid.Equals(telephoneNumber))
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

		// parse backwards
		public override RDN[] fromString(string dirName)
		{
			RDN[] tmp = IETFUtils.rDNsFromString(dirName, this);
			RDN[] res = new RDN[tmp.Length];

			for (int i = 0; i != tmp.Length; i++)
			{
				res[res.Length - i - 1] = tmp[i];
			}

			return res;
		}

		// convert in reverse
		public override string ToString(X500Name name)
		{
			StringBuffer buf = new StringBuffer();
			bool first = true;

			RDN[] rdns = name.getRDNs();

			for (int i = rdns.Length - 1; i >= 0; i--)
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