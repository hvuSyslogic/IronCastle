using BouncyCastle.Core.Port;
using org.bouncycastle.asn1.x500;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509.sigi
{

	
	/// <summary>
	/// Contains personal data for the otherName field in the subjectAltNames
	/// extension.
	/// 
	/// <pre>
	///     PersonalData ::= SEQUENCE {
	///       nameOrPseudonym NameOrPseudonym,
	///       nameDistinguisher [0] INTEGER OPTIONAL,
	///       dateOfBirth [1] GeneralizedTime OPTIONAL,
	///       placeOfBirth [2] DirectoryString OPTIONAL,
	///       gender [3] PrintableString OPTIONAL,
	///       postalAddress [4] DirectoryString OPTIONAL
	///       }
	/// </pre>
	/// </summary>
	/// <seealso cref= org.bouncycastle.asn1.x509.sigi.NameOrPseudonym </seealso>
	/// <seealso cref= org.bouncycastle.asn1.x509.sigi.SigIObjectIdentifiers </seealso>
	public class PersonalData : ASN1Object
	{
		private NameOrPseudonym nameOrPseudonym;
		private BigInteger nameDistinguisher;
		private ASN1GeneralizedTime dateOfBirth;
		private DirectoryString placeOfBirth;
		private string gender;
		private DirectoryString postalAddress;

		public static PersonalData getInstance(object obj)
		{
			if (obj == null || obj is PersonalData)
			{
				return (PersonalData)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new PersonalData((ASN1Sequence)obj);
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Constructor from ASN1Sequence.
		/// <para>
		/// The sequence is of type NameOrPseudonym:
		/// <pre>
		///     PersonalData ::= SEQUENCE {
		///       nameOrPseudonym NameOrPseudonym,
		///       nameDistinguisher [0] INTEGER OPTIONAL,
		///       dateOfBirth [1] GeneralizedTime OPTIONAL,
		///       placeOfBirth [2] DirectoryString OPTIONAL,
		///       gender [3] PrintableString OPTIONAL,
		///       postalAddress [4] DirectoryString OPTIONAL
		///       }
		/// </pre>
		/// </para> </summary>
		/// <param name="seq"> The ASN.1 sequence. </param>
		private PersonalData(ASN1Sequence seq)
		{
			if (seq.size() < 1)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			Enumeration e = seq.getObjects();

			nameOrPseudonym = NameOrPseudonym.getInstance(e.nextElement());

			while (e.hasMoreElements())
			{
				ASN1TaggedObject o = ASN1TaggedObject.getInstance(e.nextElement());
				int tag = o.getTagNo();
				switch (tag)
				{
					case 0:
						nameDistinguisher = ASN1Integer.getInstance(o, false).getValue();
						break;
					case 1:
						dateOfBirth = ASN1GeneralizedTime.getInstance(o, false);
						break;
					case 2:
						placeOfBirth = DirectoryString.getInstance(o, true);
						break;
					case 3:
						gender = DERPrintableString.getInstance(o, false).getString();
						break;
					case 4:
						postalAddress = DirectoryString.getInstance(o, true);
						break;
					default:
						throw new IllegalArgumentException("Bad tag number: " + o.getTagNo());
				}
			}
		}

		/// <summary>
		/// Constructor from a given details.
		/// </summary>
		/// <param name="nameOrPseudonym">   Name or pseudonym. </param>
		/// <param name="nameDistinguisher"> Name distinguisher. </param>
		/// <param name="dateOfBirth">       Date of birth. </param>
		/// <param name="placeOfBirth">      Place of birth. </param>
		/// <param name="gender">            Gender. </param>
		/// <param name="postalAddress">     Postal Address. </param>
		public PersonalData(NameOrPseudonym nameOrPseudonym, BigInteger nameDistinguisher, ASN1GeneralizedTime dateOfBirth, DirectoryString placeOfBirth, string gender, DirectoryString postalAddress)
		{
			this.nameOrPseudonym = nameOrPseudonym;
			this.dateOfBirth = dateOfBirth;
			this.gender = gender;
			this.nameDistinguisher = nameDistinguisher;
			this.postalAddress = postalAddress;
			this.placeOfBirth = placeOfBirth;
		}

		public virtual NameOrPseudonym getNameOrPseudonym()
		{
			return nameOrPseudonym;
		}

		public virtual BigInteger getNameDistinguisher()
		{
			return nameDistinguisher;
		}

		public virtual ASN1GeneralizedTime getDateOfBirth()
		{
			return dateOfBirth;
		}

		public virtual DirectoryString getPlaceOfBirth()
		{
			return placeOfBirth;
		}

		public virtual string getGender()
		{
			return gender;
		}

		public virtual DirectoryString getPostalAddress()
		{
			return postalAddress;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <para>
		/// Returns:
		/// <pre>
		///     PersonalData ::= SEQUENCE {
		///       nameOrPseudonym NameOrPseudonym,
		///       nameDistinguisher [0] INTEGER OPTIONAL,
		///       dateOfBirth [1] GeneralizedTime OPTIONAL,
		///       placeOfBirth [2] DirectoryString OPTIONAL,
		///       gender [3] PrintableString OPTIONAL,
		///       postalAddress [4] DirectoryString OPTIONAL
		///       }
		/// </pre>
		/// 
		/// </para>
		/// </summary>
		/// <returns> a DERObject </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector vec = new ASN1EncodableVector();
			vec.add(nameOrPseudonym);
			if (nameDistinguisher != null)
			{
				vec.add(new DERTaggedObject(false, 0, new ASN1Integer(nameDistinguisher)));
			}
			if (dateOfBirth != null)
			{
				vec.add(new DERTaggedObject(false, 1, dateOfBirth));
			}
			if (placeOfBirth != null)
			{
				vec.add(new DERTaggedObject(true, 2, placeOfBirth));
			}
			if (!string.ReferenceEquals(gender, null))
			{
				vec.add(new DERTaggedObject(false, 3, new DERPrintableString(gender, true)));
			}
			if (postalAddress != null)
			{
				vec.add(new DERTaggedObject(true, 4, postalAddress));
			}
			return new DERSequence(vec);
		}
	}

}