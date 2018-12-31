using org.bouncycastle.asn1.x500;
using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.isismtt.x509
{

			
	/// <summary>
	/// Attribute to indicate that the certificate holder may sign in the name of a
	/// third person.
	/// <para>
	/// ISIS-MTT PROFILE: The corresponding ProcurationSyntax contains either the
	/// name of the person who is represented (subcomponent thirdPerson) or a
	/// reference to his/her base certificate (in the component signingFor,
	/// subcomponent certRef), furthermore the optional components country and
	/// typeSubstitution to indicate the country whose laws apply, and respectively
	/// the type of procuration (e.g. manager, procuration, custody).
	/// </para>
	/// <para>
	/// ISIS-MTT PROFILE: The GeneralName MUST be of type directoryName and MAY only
	/// contain: - RFC3039 attributes, except pseudonym (countryName, commonName,
	/// surname, givenName, serialNumber, organizationName, organizationalUnitName,
	/// stateOrProvincename, localityName, postalAddress) and - SubjectDirectoryName
	/// attributes (title, dateOfBirth, placeOfBirth, gender, countryOfCitizenship,
	/// countryOfResidence and NameAtBirth).
	/// 
	/// <pre>
	///               ProcurationSyntax ::= SEQUENCE {
	///                 country [1] EXPLICIT PrintableString(SIZE(2)) OPTIONAL,
	///                 typeOfSubstitution [2] EXPLICIT DirectoryString (SIZE(1..128)) OPTIONAL,
	///                 signingFor [3] EXPLICIT SigningFor 
	///               }
	/// 
	///               SigningFor ::= CHOICE 
	///               { 
	///                 thirdPerson GeneralName,
	///                 certRef IssuerSerial 
	///               }
	/// </pre>
	/// 
	/// </para>
	/// </summary>
	public class ProcurationSyntax : ASN1Object
	{
		private string country;
		private DirectoryString typeOfSubstitution;

		private GeneralName thirdPerson;
		private IssuerSerial certRef;

		public static ProcurationSyntax getInstance(object obj)
		{
			if (obj == null || obj is ProcurationSyntax)
			{
				return (ProcurationSyntax)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new ProcurationSyntax((ASN1Sequence)obj);
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Constructor from ASN1Sequence.
		/// <para>
		/// The sequence is of type ProcurationSyntax:
		/// <pre>
		///               ProcurationSyntax ::= SEQUENCE {
		///                 country [1] EXPLICIT PrintableString(SIZE(2)) OPTIONAL,
		///                 typeOfSubstitution [2] EXPLICIT DirectoryString (SIZE(1..128)) OPTIONAL,
		///                 signingFor [3] EXPLICIT SigningFor
		///               }
		/// 
		///               SigningFor ::= CHOICE
		///               {
		///                 thirdPerson GeneralName,
		///                 certRef IssuerSerial
		///               }
		/// </pre>
		/// </para> </summary>
		/// <param name="seq"> The ASN.1 sequence. </param>
		private ProcurationSyntax(ASN1Sequence seq)
		{
			if (seq.size() < 1 || seq.size() > 3)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}
			Enumeration e = seq.getObjects();

			while (e.hasMoreElements())
			{
				ASN1TaggedObject o = ASN1TaggedObject.getInstance(e.nextElement());
				switch (o.getTagNo())
				{
					case 1:
						country = DERPrintableString.getInstance(o, true).getString();
						break;
					case 2:
						typeOfSubstitution = DirectoryString.getInstance(o, true);
						break;
					case 3:
						ASN1Encodable signingFor = o.getObject();
						if (signingFor is ASN1TaggedObject)
						{
							thirdPerson = GeneralName.getInstance(signingFor);
						}
						else
						{
							certRef = IssuerSerial.getInstance(signingFor);
						}
						break;
					default:
						throw new IllegalArgumentException("Bad tag number: " + o.getTagNo());
				}
			}
		}

		/// <summary>
		/// Constructor from a given details.
		/// <para>
		/// Either <code>generalName</code> or <code>certRef</code> MUST be
		/// <code>null</code>.
		/// 
		/// </para>
		/// </summary>
		/// <param name="country">            The country code whose laws apply. </param>
		/// <param name="typeOfSubstitution"> The type of procuration. </param>
		/// <param name="certRef">            Reference to certificate of the person who is represented. </param>
		public ProcurationSyntax(string country, DirectoryString typeOfSubstitution, IssuerSerial certRef)
		{
			this.country = country;
			this.typeOfSubstitution = typeOfSubstitution;
			this.thirdPerson = null;
			this.certRef = certRef;
		}

		/// <summary>
		/// Constructor from a given details.
		/// <para>
		/// Either <code>generalName</code> or <code>certRef</code> MUST be
		/// <code>null</code>.
		/// 
		/// </para>
		/// </summary>
		/// <param name="country">            The country code whose laws apply. </param>
		/// <param name="typeOfSubstitution"> The type of procuration. </param>
		/// <param name="thirdPerson">        The GeneralName of the person who is represented. </param>
		public ProcurationSyntax(string country, DirectoryString typeOfSubstitution, GeneralName thirdPerson)
		{
			this.country = country;
			this.typeOfSubstitution = typeOfSubstitution;
			this.thirdPerson = thirdPerson;
			this.certRef = null;
		}

		public virtual string getCountry()
		{
			return country;
		}

		public virtual DirectoryString getTypeOfSubstitution()
		{
			return typeOfSubstitution;
		}

		public virtual GeneralName getThirdPerson()
		{
			return thirdPerson;
		}

		public virtual IssuerSerial getCertRef()
		{
			return certRef;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <para>
		/// Returns:
		/// <pre>
		///               ProcurationSyntax ::= SEQUENCE {
		///                 country [1] EXPLICIT PrintableString(SIZE(2)) OPTIONAL,
		///                 typeOfSubstitution [2] EXPLICIT DirectoryString (SIZE(1..128)) OPTIONAL,
		///                 signingFor [3] EXPLICIT SigningFor
		///               }
		/// 
		///               SigningFor ::= CHOICE
		///               {
		///                 thirdPerson GeneralName,
		///                 certRef IssuerSerial
		///               }
		/// </pre>
		/// 
		/// </para>
		/// </summary>
		/// <returns> a DERObject </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector vec = new ASN1EncodableVector();
			if (!string.ReferenceEquals(country, null))
			{
				vec.add(new DERTaggedObject(true, 1, new DERPrintableString(country, true)));
			}
			if (typeOfSubstitution != null)
			{
				vec.add(new DERTaggedObject(true, 2, typeOfSubstitution));
			}
			if (thirdPerson != null)
			{
				vec.add(new DERTaggedObject(true, 3, thirdPerson));
			}
			else
			{
				vec.add(new DERTaggedObject(true, 3, certRef));
			}

			return new DERSequence(vec);
		}
	}

}