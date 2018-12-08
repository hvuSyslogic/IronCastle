using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.isismtt.x509
{

	/// <summary>
	/// A declaration of majority.
	/// 
	/// <pre>
	///           DeclarationOfMajoritySyntax ::= CHOICE
	///           {
	///             notYoungerThan [0] IMPLICIT INTEGER,
	///             fullAgeAtCountry [1] IMPLICIT SEQUENCE
	///             {
	///               fullAge BOOLEAN DEFAULT TRUE,
	///               country PrintableString (SIZE(2))
	///             }
	///             dateOfBirth [2] IMPLICIT GeneralizedTime
	///           }
	/// </pre>
	/// <para>
	/// fullAgeAtCountry indicates the majority of the owner with respect to the laws
	/// of a specific country.
	/// </para>
	/// </summary>
	public class DeclarationOfMajority : ASN1Object, ASN1Choice
	{
//JAVA TO C# CONVERTER NOTE: Fields cannot have the same name as methods:
		public const int notYoungerThan_Renamed = 0;
//JAVA TO C# CONVERTER NOTE: Fields cannot have the same name as methods:
		public const int fullAgeAtCountry_Renamed = 1;
		public const int dateOfBirth = 2;

		private ASN1TaggedObject declaration;

		public DeclarationOfMajority(int notYoungerThan)
		{
			declaration = new DERTaggedObject(false, 0, new ASN1Integer(notYoungerThan));
		}

		public DeclarationOfMajority(bool fullAge, string country)
		{
			if (country.Length > 2)
			{
				throw new IllegalArgumentException("country can only be 2 characters");
			}

			if (fullAge)
			{
				declaration = new DERTaggedObject(false, 1, new DERSequence(new DERPrintableString(country, true)));
			}
			else
			{
				ASN1EncodableVector v = new ASN1EncodableVector();

				v.add(ASN1Boolean.FALSE);
				v.add(new DERPrintableString(country, true));

				declaration = new DERTaggedObject(false, 1, new DERSequence(v));
			}
		}

		public DeclarationOfMajority(ASN1GeneralizedTime dateOfBirth)
		{
			declaration = new DERTaggedObject(false, 2, dateOfBirth);
		}

		public static DeclarationOfMajority getInstance(object obj)
		{
			if (obj == null || obj is DeclarationOfMajority)
			{
				return (DeclarationOfMajority)obj;
			}

			if (obj is ASN1TaggedObject)
			{
				return new DeclarationOfMajority((ASN1TaggedObject)obj);
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		private DeclarationOfMajority(ASN1TaggedObject o)
		{
			if (o.getTagNo() > 2)
			{
					throw new IllegalArgumentException("Bad tag number: " + o.getTagNo());
			}
			declaration = o;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <para>
		/// Returns:
		/// <pre>
		///           DeclarationOfMajoritySyntax ::= CHOICE
		///           {
		///             notYoungerThan [0] IMPLICIT INTEGER,
		///             fullAgeAtCountry [1] IMPLICIT SEQUENCE
		///             {
		///               fullAge BOOLEAN DEFAULT TRUE,
		///               country PrintableString (SIZE(2))
		///             }
		///             dateOfBirth [2] IMPLICIT GeneralizedTime
		///           }
		/// </pre>
		/// 
		/// </para>
		/// </summary>
		/// <returns> a DERObject </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return declaration;
		}

		public virtual int getType()
		{
			return declaration.getTagNo();
		}

		/// <returns> notYoungerThan if that's what we are, -1 otherwise </returns>
		public virtual int notYoungerThan()
		{
			if (declaration.getTagNo() != 0)
			{
				return -1;
			}

			return ASN1Integer.getInstance(declaration, false).getValue().intValue();
		}

		public virtual ASN1Sequence fullAgeAtCountry()
		{
			if (declaration.getTagNo() != 1)
			{
				return null;
			}

			return ASN1Sequence.getInstance(declaration, false);
		}

		public virtual ASN1GeneralizedTime getDateOfBirth()
		{
			if (declaration.getTagNo() != 2)
			{
				return null;
			}

			return ASN1GeneralizedTime.getInstance(declaration, false);
		}
	}

}