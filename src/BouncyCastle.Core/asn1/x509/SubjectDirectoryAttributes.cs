using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{


	/// <summary>
	/// This extension may contain further X.500 attributes of the subject. See also
	/// RFC 3039.
	/// 
	/// <pre>
	///     SubjectDirectoryAttributes ::= Attributes
	///     Attributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
	///     Attribute ::= SEQUENCE 
	///     {
	///       type AttributeType 
	///       values SET OF AttributeValue 
	///     }
	/// 
	///     AttributeType ::= OBJECT IDENTIFIER
	///     AttributeValue ::= ANY DEFINED BY AttributeType
	/// </pre>
	/// </summary>
	/// <seealso cref= org.bouncycastle.asn1.x500.style.BCStyle for AttributeType ObjectIdentifiers. </seealso>
	public class SubjectDirectoryAttributes : ASN1Object
	{
		private Vector attributes = new Vector();

		public static SubjectDirectoryAttributes getInstance(object obj)
		{
			if (obj is SubjectDirectoryAttributes)
			{
				return (SubjectDirectoryAttributes)obj;
			}

			if (obj != null)
			{
				return new SubjectDirectoryAttributes(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// <summary>
		/// Constructor from ASN1Sequence.
		/// 
		/// The sequence is of type SubjectDirectoryAttributes:
		/// 
		/// <pre>
		///      SubjectDirectoryAttributes ::= Attributes
		///      Attributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
		///      Attribute ::= SEQUENCE 
		///      {
		///        type AttributeType 
		///        values SET OF AttributeValue 
		///      }
		/// 
		///      AttributeType ::= OBJECT IDENTIFIER
		///      AttributeValue ::= ANY DEFINED BY AttributeType
		/// </pre>
		/// </summary>
		/// <param name="seq">
		///            The ASN.1 sequence. </param>
		private SubjectDirectoryAttributes(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			while (e.hasMoreElements())
			{
				ASN1Sequence s = ASN1Sequence.getInstance(e.nextElement());
				attributes.addElement(Attribute.getInstance(s));
			}
		}

		/// <summary>
		/// Constructor from a vector of attributes.
		/// 
		/// The vector consists of attributes of type <seealso cref="Attribute Attribute"/>
		/// </summary>
		/// <param name="attributes">
		///            The attributes.
		///  </param>
		public SubjectDirectoryAttributes(Vector attributes)
		{
			Enumeration e = attributes.elements();

			while (e.hasMoreElements())
			{
				this.attributes.addElement(e.nextElement());
			}
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// 
		/// Returns:
		/// 
		/// <pre>
		///      SubjectDirectoryAttributes ::= Attributes
		///      Attributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
		///      Attribute ::= SEQUENCE 
		///      {
		///        type AttributeType 
		///        values SET OF AttributeValue 
		///      }
		/// 
		///      AttributeType ::= OBJECT IDENTIFIER
		///      AttributeValue ::= ANY DEFINED BY AttributeType
		/// </pre>
		/// </summary>
		/// <returns> a ASN1Primitive </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector vec = new ASN1EncodableVector();
			Enumeration e = attributes.elements();

			while (e.hasMoreElements())
			{

				vec.add((Attribute)e.nextElement());
			}

			return new DERSequence(vec);
		}

		/// <returns> Returns the attributes. </returns>
		public virtual Vector getAttributes()
		{
			return attributes;
		}
	}

}