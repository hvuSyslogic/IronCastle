using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x500
{

	/// <summary>
	/// The DirectoryString CHOICE object.
	/// </summary>
	public class DirectoryString : ASN1Object, ASN1Choice, ASN1String
	{
		private ASN1String @string;

		public static DirectoryString getInstance(object o)
		{
			if (o == null || o is DirectoryString)
			{
				return (DirectoryString)o;
			}

			if (o is DERT61String)
			{
				return new DirectoryString((DERT61String)o);
			}

			if (o is DERPrintableString)
			{
				return new DirectoryString((DERPrintableString)o);
			}

			if (o is DERUniversalString)
			{
				return new DirectoryString((DERUniversalString)o);
			}

			if (o is DERUTF8String)
			{
				return new DirectoryString((DERUTF8String)o);
			}

			if (o is DERBMPString)
			{
				return new DirectoryString((DERBMPString)o);
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + o.GetType().getName());
		}

		public static DirectoryString getInstance(ASN1TaggedObject o, bool @explicit)
		{
			if (!@explicit)
			{
				throw new IllegalArgumentException("choice item must be explicitly tagged");
			}

			return getInstance(o.getObject());
		}

		private DirectoryString(DERT61String @string)
		{
			this.@string = @string;
		}

		private DirectoryString(DERPrintableString @string)
		{
			this.@string = @string;
		}

		private DirectoryString(DERUniversalString @string)
		{
			this.@string = @string;
		}

		private DirectoryString(DERUTF8String @string)
		{
			this.@string = @string;
		}

		private DirectoryString(DERBMPString @string)
		{
			this.@string = @string;
		}

		public DirectoryString(string @string)
		{
			this.@string = new DERUTF8String(@string);
		}

		public virtual string getString()
		{
			return @string.getString();
		}

		public override string ToString()
		{
			return @string.getString();
		}

		/// <summary>
		/// <pre>
		///  DirectoryString ::= CHOICE {
		///    teletexString               TeletexString (SIZE (1..MAX)),
		///    printableString             PrintableString (SIZE (1..MAX)),
		///    universalString             UniversalString (SIZE (1..MAX)),
		///    utf8String                  UTF8String (SIZE (1..MAX)),
		///    bmpString                   BMPString (SIZE (1..MAX))  }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return ((ASN1Encodable)@string).toASN1Primitive();
		}
	}

}