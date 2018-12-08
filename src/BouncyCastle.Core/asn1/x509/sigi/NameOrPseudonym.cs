using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509.sigi
{

	using DirectoryString = org.bouncycastle.asn1.x500.DirectoryString;

	/// <summary>
	/// Structure for a name or pseudonym.
	/// 
	/// <pre>
	///       NameOrPseudonym ::= CHOICE {
	///            surAndGivenName SEQUENCE {
	///              surName DirectoryString,
	///              givenName SEQUENCE OF DirectoryString 
	///         },
	///            pseudonym DirectoryString 
	///       }
	/// </pre>
	/// </summary>
	/// <seealso cref= org.bouncycastle.asn1.x509.sigi.PersonalData
	///  </seealso>
	public class NameOrPseudonym : ASN1Object, ASN1Choice
	{
		private DirectoryString pseudonym;

		private DirectoryString surname;

		private ASN1Sequence givenName;

		public static NameOrPseudonym getInstance(object obj)
		{
			if (obj == null || obj is NameOrPseudonym)
			{
				return (NameOrPseudonym)obj;
			}

			if (obj is ASN1String)
			{
				return new NameOrPseudonym(DirectoryString.getInstance(obj));
			}

			if (obj is ASN1Sequence)
			{
				return new NameOrPseudonym((ASN1Sequence)obj);
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Constructor from DirectoryString.
		/// <para>
		/// The sequence is of type NameOrPseudonym:
		/// <pre>
		///       NameOrPseudonym ::= CHOICE {
		///            surAndGivenName SEQUENCE {
		///              surName DirectoryString,
		///              givenName SEQUENCE OF DirectoryString
		///         },
		///            pseudonym DirectoryString
		///       }
		/// </pre>
		/// </para>
		/// </summary>
		/// <param name="pseudonym"> pseudonym value to use. </param>
		public NameOrPseudonym(DirectoryString pseudonym)
		{
			this.pseudonym = pseudonym;
		}

		/// <summary>
		/// Constructor from ASN1Sequence.
		/// <para>
		/// The sequence is of type NameOrPseudonym:
		/// <pre>
		///       NameOrPseudonym ::= CHOICE {
		///            surAndGivenName SEQUENCE {
		///              surName DirectoryString,
		///              givenName SEQUENCE OF DirectoryString
		///         },
		///            pseudonym DirectoryString
		///       }
		/// </pre>
		/// </para> </summary>
		/// <param name="seq"> The ASN.1 sequence. </param>
		private NameOrPseudonym(ASN1Sequence seq)
		{
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			if (!(seq.getObjectAt(0) is ASN1String))
			{
				throw new IllegalArgumentException("Bad object encountered: " + seq.getObjectAt(0).GetType());
			}

			surname = DirectoryString.getInstance(seq.getObjectAt(0));
			givenName = ASN1Sequence.getInstance(seq.getObjectAt(1));
		}

		/// <summary>
		/// Constructor from a given details.
		/// </summary>
		/// <param name="pseudonym"> The pseudonym. </param>
		public NameOrPseudonym(string pseudonym) : this(new DirectoryString(pseudonym))
		{
		}

		/// <summary>
		/// Constructor from a given details.
		/// </summary>
		/// <param name="surname">   The surname. </param>
		/// <param name="givenName"> A sequence of directory strings making up the givenName </param>
		public NameOrPseudonym(DirectoryString surname, ASN1Sequence givenName)
		{
			this.surname = surname;
			this.givenName = givenName;
		}

		public virtual DirectoryString getPseudonym()
		{
			return pseudonym;
		}

		public virtual DirectoryString getSurname()
		{
			return surname;
		}

		public virtual DirectoryString[] getGivenName()
		{
			DirectoryString[] items = new DirectoryString[givenName.size()];
			int count = 0;
			for (Enumeration e = givenName.getObjects(); e.hasMoreElements();)
			{
				items[count++] = DirectoryString.getInstance(e.nextElement());
			}
			return items;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <para>
		/// Returns:
		/// <pre>
		///       NameOrPseudonym ::= CHOICE {
		///            surAndGivenName SEQUENCE {
		///              surName DirectoryString,
		///              givenName SEQUENCE OF DirectoryString
		///         },
		///            pseudonym DirectoryString
		///       }
		/// </pre>
		/// 
		/// </para>
		/// </summary>
		/// <returns> a DERObject </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			if (pseudonym != null)
			{
				return pseudonym.toASN1Primitive();
			}
			else
			{
				ASN1EncodableVector vec1 = new ASN1EncodableVector();
				vec1.add(surname);
				vec1.add(givenName);
				return new DERSequence(vec1);
			}
		}
	}

}