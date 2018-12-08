using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-6.2.5">RFC 5652</a>:
	/// Content encryption key delivery mechanisms.
	/// <pre>
	/// OtherRecipientInfo ::= SEQUENCE {
	///    oriType OBJECT IDENTIFIER,
	///    oriValue ANY DEFINED BY oriType }
	/// </pre>
	/// </summary>
	public class OtherRecipientInfo : ASN1Object
	{
		private ASN1ObjectIdentifier oriType;
		private ASN1Encodable oriValue;

		public OtherRecipientInfo(ASN1ObjectIdentifier oriType, ASN1Encodable oriValue)
		{
			this.oriType = oriType;
			this.oriValue = oriValue;
		}

		private OtherRecipientInfo(ASN1Sequence seq)
		{
			oriType = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
			oriValue = seq.getObjectAt(1);
		}

		/// <summary>
		/// Return a OtherRecipientInfo object from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///          tagged object cannot be converted. </exception>
		public static OtherRecipientInfo getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Return a OtherRecipientInfo object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="PasswordRecipientInfo"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with OtherRecipientInfo structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static OtherRecipientInfo getInstance(object obj)
		{
			if (obj is OtherRecipientInfo)
			{
				return (OtherRecipientInfo)obj;
			}

			if (obj != null)
			{
				return new OtherRecipientInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1ObjectIdentifier getType()
		{
			return oriType;
		}

		public virtual ASN1Encodable getValue()
		{
			return oriValue;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(oriType);
			v.add(oriValue);

			return new DERSequence(v);
		}
	}

}