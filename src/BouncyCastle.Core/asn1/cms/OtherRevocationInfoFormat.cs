using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-10.2.1">RFC 5652</a>: OtherRevocationInfoFormat object.
	/// <para>
	/// <pre>
	/// OtherRevocationInfoFormat ::= SEQUENCE {
	///      otherRevInfoFormat OBJECT IDENTIFIER,
	///      otherRevInfo ANY DEFINED BY otherRevInfoFormat }
	/// </pre>
	/// </para>
	/// </summary>
	public class OtherRevocationInfoFormat : ASN1Object
	{
		private ASN1ObjectIdentifier otherRevInfoFormat;
		private ASN1Encodable otherRevInfo;

		public OtherRevocationInfoFormat(ASN1ObjectIdentifier otherRevInfoFormat, ASN1Encodable otherRevInfo)
		{
			this.otherRevInfoFormat = otherRevInfoFormat;
			this.otherRevInfo = otherRevInfo;
		}

		private OtherRevocationInfoFormat(ASN1Sequence seq)
		{
			otherRevInfoFormat = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
			otherRevInfo = seq.getObjectAt(1);
		}

		/// <summary>
		/// Return a OtherRevocationInfoFormat object from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///          tagged object cannot be converted. </exception>
		public static OtherRevocationInfoFormat getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Return a OtherRevocationInfoFormat object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="OtherRevocationInfoFormat"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with OtherRevocationInfoFormat structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static OtherRevocationInfoFormat getInstance(object obj)
		{
			if (obj is OtherRevocationInfoFormat)
			{
				return (OtherRevocationInfoFormat)obj;
			}

			if (obj != null)
			{
				return new OtherRevocationInfoFormat(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1ObjectIdentifier getInfoFormat()
		{
			return otherRevInfoFormat;
		}

		public virtual ASN1Encodable getInfo()
		{
			return otherRevInfo;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(otherRevInfoFormat);
			v.add(otherRevInfo);

			return new DERSequence(v);
		}
	}

}