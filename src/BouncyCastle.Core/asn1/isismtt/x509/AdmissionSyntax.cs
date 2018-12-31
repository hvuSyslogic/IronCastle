using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.isismtt.x509
{

	
	/// <summary>
	/// Attribute to indicate admissions to certain professions.
	/// 
	/// <pre>
	///     AdmissionSyntax ::= SEQUENCE
	///     {
	///       admissionAuthority GeneralName OPTIONAL,
	///       contentsOfAdmissions SEQUENCE OF Admissions
	///     }
	/// 
	///     Admissions ::= SEQUENCE
	///     {
	///       admissionAuthority [0] EXPLICIT GeneralName OPTIONAL
	///       namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL
	///       professionInfos SEQUENCE OF ProfessionInfo
	///     }
	/// 
	///     NamingAuthority ::= SEQUENCE
	///     {
	///       namingAuthorityId OBJECT IDENTIFIER OPTIONAL,
	///       namingAuthorityUrl IA5String OPTIONAL,
	///       namingAuthorityText DirectoryString(SIZE(1..128)) OPTIONAL
	///     }
	/// 
	///     ProfessionInfo ::= SEQUENCE
	///     {
	///       namingAuthority [0] EXPLICIT NamingAuthority OPTIONAL,
	///       professionItems SEQUENCE OF DirectoryString (SIZE(1..128)),
	///       professionOIDs SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
	///       registrationNumber PrintableString(SIZE(1..128)) OPTIONAL,
	///       addProfessionInfo OCTET STRING OPTIONAL
	///     }
	/// </pre>
	/// <para>
	/// ISIS-MTT PROFILE: The relatively complex structure of AdmissionSyntax
	/// supports the following concepts and requirements:
	/// <ul>
	/// <li> External institutions (e.g. professional associations, chambers, unions,
	/// administrative bodies, companies, etc.), which are responsible for granting
	/// and verifying professional admissions, are indicated by means of the data
	/// field admissionAuthority. An admission authority is indicated by a
	/// GeneralName object. Here an X.501 directory name (distinguished name) can be
	/// indicated in the field directoryName, a URL address can be indicated in the
	/// field uniformResourceIdentifier, and an object identifier can be indicated in
	/// the field registeredId.
	/// <li> The names of authorities which are responsible for the administration of
	/// title registers are indicated in the data field namingAuthority. The name of
	/// the authority can be identified by an object identifier in the field
	/// namingAuthorityId, by means of a text string in the field
	/// namingAuthorityText, by means of a URL address in the field
	/// namingAuthorityUrl, or by a combination of them. For example, the text string
	/// can contain the name of the authority, the country and the name of the title
	/// register. The URL-option refers to a web page which contains lists with
	/// �officially� registered professions (text and possibly OID) as well as
	/// further information on these professions. Object identifiers for the
	/// component namingAuthorityId are grouped under the OID-branch
	/// id-isis-at-namingAuthorities and must be applied for.
	/// <li>See
	/// http://www.teletrust.de/anwend.asp?Id=30200&amp;Sprache=E_&amp;HomePG=0 for
	/// an application form and http://www.teletrust.de/links.asp?id=30220,11
	/// for an overview of registered naming authorities.
	/// <li> By means of the data type ProfessionInfo certain professions,
	/// specializations, disciplines, fields of activity, etc. are identified. A
	/// profession is represented by one or more text strings, resp. profession OIDs
	/// in the fields professionItems and professionOIDs and by a registration number
	/// in the field registrationNumber. An indication in text form must always be
	/// present, whereas the other indications are optional. The component
	/// addProfessionInfo may contain additional applicationspecific information in
	/// DER-encoded form.
	/// </ul>
	/// </para>
	/// <para>
	/// By means of different namingAuthority-OIDs or profession OIDs hierarchies of
	/// professions, specializations, disciplines, fields of activity, etc. can be
	/// expressed. The issuing admission authority should always be indicated (field
	/// admissionAuthority), whenever a registration number is presented. Still,
	/// information on admissions can be given without indicating an admission or a
	/// naming authority by the exclusive use of the component professionItems. In
	/// this case the certification authority is responsible for the verification of
	/// the admission information.
	/// </para>
	/// <para>
	/// This attribute is single-valued. Still, several admissions can be captured in
	/// the sequence structure of the component contentsOfAdmissions of
	/// AdmissionSyntax or in the component professionInfos of Admissions. The
	/// component admissionAuthority of AdmissionSyntax serves as default value for
	/// the component admissionAuthority of Admissions. Within the latter component
	/// the default value can be overwritten, in case that another authority is
	/// responsible. The component namingAuthority of Admissions serves as a default
	/// value for the component namingAuthority of ProfessionInfo. Within the latter
	/// component the default value can be overwritten, in case that another naming
	/// authority needs to be recorded.
	/// </para>
	/// <para>
	/// The length of the string objects is limited to 128 characters. It is
	/// recommended to indicate a namingAuthorityURL in all issued attribute
	/// certificates. If a namingAuthorityURL is indicated, the field professionItems
	/// of ProfessionInfo should contain only registered titles. If the field
	/// professionOIDs exists, it has to contain the OIDs of the professions listed
	/// in professionItems in the same order. In general, the field professionInfos
	/// should contain only one entry, unless the admissions that are to be listed
	/// are logically connected (e.g. they have been issued under the same admission
	/// number).
	/// 
	/// </para>
	/// </summary>
	/// <seealso cref= org.bouncycastle.asn1.isismtt.x509.Admissions </seealso>
	/// <seealso cref= org.bouncycastle.asn1.isismtt.x509.ProfessionInfo </seealso>
	/// <seealso cref= org.bouncycastle.asn1.isismtt.x509.NamingAuthority </seealso>
	public class AdmissionSyntax : ASN1Object
	{

		private GeneralName admissionAuthority;

		private ASN1Sequence contentsOfAdmissions;

		public static AdmissionSyntax getInstance(object obj)
		{
			if (obj == null || obj is AdmissionSyntax)
			{
				return (AdmissionSyntax)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new AdmissionSyntax((ASN1Sequence)obj);
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Constructor from ASN1Sequence.
		/// <para>
		/// The sequence is of type ProcurationSyntax:
		/// <pre>
		///     AdmissionSyntax ::= SEQUENCE
		///     {
		///       admissionAuthority GeneralName OPTIONAL,
		///       contentsOfAdmissions SEQUENCE OF Admissions
		///     }
		/// 
		///     Admissions ::= SEQUENCE
		///     {
		///       admissionAuthority [0] EXPLICIT GeneralName OPTIONAL
		///       namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL
		///       professionInfos SEQUENCE OF ProfessionInfo
		///     }
		/// 
		///     NamingAuthority ::= SEQUENCE
		///     {
		///       namingAuthorityId OBJECT IDENTIFIER OPTIONAL,
		///       namingAuthorityUrl IA5String OPTIONAL,
		///       namingAuthorityText DirectoryString(SIZE(1..128)) OPTIONAL
		///     }
		/// 
		///     ProfessionInfo ::= SEQUENCE
		///     {
		///       namingAuthority [0] EXPLICIT NamingAuthority OPTIONAL,
		///       professionItems SEQUENCE OF DirectoryString (SIZE(1..128)),
		///       professionOIDs SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
		///       registrationNumber PrintableString(SIZE(1..128)) OPTIONAL,
		///       addProfessionInfo OCTET STRING OPTIONAL
		///     }
		/// </pre>
		/// </para> </summary>
		/// <param name="seq"> The ASN.1 sequence. </param>
		private AdmissionSyntax(ASN1Sequence seq)
		{
			switch (seq.size())
			{
			case 1:
				contentsOfAdmissions = DERSequence.getInstance(seq.getObjectAt(0));
				break;
			case 2:
				admissionAuthority = GeneralName.getInstance(seq.getObjectAt(0));
				contentsOfAdmissions = DERSequence.getInstance(seq.getObjectAt(1));
				break;
			default:
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}
		}

		/// <summary>
		/// Constructor from given details.
		/// </summary>
		/// <param name="admissionAuthority">   The admission authority. </param>
		/// <param name="contentsOfAdmissions"> The admissions. </param>
		public AdmissionSyntax(GeneralName admissionAuthority, ASN1Sequence contentsOfAdmissions)
		{
			this.admissionAuthority = admissionAuthority;
			this.contentsOfAdmissions = contentsOfAdmissions;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <para>
		/// Returns:
		/// <pre>
		///     AdmissionSyntax ::= SEQUENCE
		///     {
		///       admissionAuthority GeneralName OPTIONAL,
		///       contentsOfAdmissions SEQUENCE OF Admissions
		///     }
		/// 
		///     Admissions ::= SEQUENCE
		///     {
		///       admissionAuthority [0] EXPLICIT GeneralName OPTIONAL
		///       namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL
		///       professionInfos SEQUENCE OF ProfessionInfo
		///     }
		/// 
		///     NamingAuthority ::= SEQUENCE
		///     {
		///       namingAuthorityId OBJECT IDENTIFIER OPTIONAL,
		///       namingAuthorityUrl IA5String OPTIONAL,
		///       namingAuthorityText DirectoryString(SIZE(1..128)) OPTIONAL
		///     }
		/// 
		///     ProfessionInfo ::= SEQUENCE
		///     {
		///       namingAuthority [0] EXPLICIT NamingAuthority OPTIONAL,
		///       professionItems SEQUENCE OF DirectoryString (SIZE(1..128)),
		///       professionOIDs SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
		///       registrationNumber PrintableString(SIZE(1..128)) OPTIONAL,
		///       addProfessionInfo OCTET STRING OPTIONAL
		///     }
		/// </pre>
		/// 
		/// </para>
		/// </summary>
		/// <returns> a DERObject </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector vec = new ASN1EncodableVector();
			if (admissionAuthority != null)
			{
				vec.add(admissionAuthority);
			}
			vec.add(contentsOfAdmissions);
			return new DERSequence(vec);
		}

		/// <returns> Returns the admissionAuthority if present, null otherwise. </returns>
		public virtual GeneralName getAdmissionAuthority()
		{
			return admissionAuthority;
		}

		/// <returns> Returns the contentsOfAdmissions. </returns>
		public virtual Admissions[] getContentsOfAdmissions()
		{
			Admissions[] admissions = new Admissions[contentsOfAdmissions.size()];
			int count = 0;
			for (Enumeration e = contentsOfAdmissions.getObjects(); e.hasMoreElements();)
			{
				admissions[count++] = Admissions.getInstance(e.nextElement());
			}
			return admissions;
		}
	}

}