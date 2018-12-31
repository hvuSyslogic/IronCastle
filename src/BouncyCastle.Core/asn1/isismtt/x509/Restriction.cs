using org.bouncycastle.asn1.x500;

namespace org.bouncycastle.asn1.isismtt.x509
{
	
	/// <summary>
	/// Some other restriction regarding the usage of this certificate.
	/// 
	/// <pre>
	///  RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
	/// </pre>
	/// </summary>
	public class Restriction : ASN1Object
	{
		private DirectoryString restriction;

		public static Restriction getInstance(object obj)
		{
			if (obj is Restriction)
			{
				return (Restriction)obj;
			}

			if (obj != null)
			{
				return new Restriction(DirectoryString.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// Constructor from DirectoryString.
		/// <para>
		/// The DirectoryString is of type RestrictionSyntax:
		/// <pre>
		///      RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
		/// </pre>
		/// </para> </summary>
		/// <param name="restriction"> A DirectoryString. </param>
		private Restriction(DirectoryString restriction)
		{
			this.restriction = restriction;
		}

		/// <summary>
		/// Constructor from a given details.
		/// </summary>
		/// <param name="restriction"> The describtion of the restriction. </param>
		public Restriction(string restriction)
		{
			this.restriction = new DirectoryString(restriction);
		}

		public virtual DirectoryString getRestriction()
		{
			return restriction;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <para>
		/// Returns:
		/// <pre>
		///      RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
		/// </pre>
		/// 
		/// </para>
		/// </summary>
		/// <returns> a DERObject </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return restriction.toASN1Primitive();
		}
	}

}