using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
	/// Content encryption key delivery mechanisms.
	/// <para>
	/// <pre>
	/// RecipientKeyIdentifier ::= SEQUENCE {
	///     subjectKeyIdentifier SubjectKeyIdentifier,
	///     date GeneralizedTime OPTIONAL,
	///     other OtherKeyAttribute OPTIONAL 
	/// }
	/// 
	/// SubjectKeyIdentifier ::= OCTET STRING
	/// </pre>
	/// </para>
	/// </summary>
	public class RecipientKeyIdentifier : ASN1Object
	{
		private ASN1OctetString subjectKeyIdentifier;
		private ASN1GeneralizedTime date;
		private OtherKeyAttribute other;

		public RecipientKeyIdentifier(ASN1OctetString subjectKeyIdentifier, ASN1GeneralizedTime date, OtherKeyAttribute other)
		{
			this.subjectKeyIdentifier = subjectKeyIdentifier;
			this.date = date;
			this.other = other;
		}

		public RecipientKeyIdentifier(byte[] subjectKeyIdentifier, ASN1GeneralizedTime date, OtherKeyAttribute other)
		{
			this.subjectKeyIdentifier = new DEROctetString(subjectKeyIdentifier);
			this.date = date;
			this.other = other;
		}

		public RecipientKeyIdentifier(byte[] subjectKeyIdentifier) : this(subjectKeyIdentifier, null, null)
		{
		}

		/// @deprecated use getInstance() 
		public RecipientKeyIdentifier(ASN1Sequence seq)
		{
			subjectKeyIdentifier = ASN1OctetString.getInstance(seq.getObjectAt(0));

			switch (seq.size())
			{
			case 1:
				break;
			case 2:
				if (seq.getObjectAt(1) is ASN1GeneralizedTime)
				{
					date = ASN1GeneralizedTime.getInstance(seq.getObjectAt(1));
				}
				else
				{
					other = OtherKeyAttribute.getInstance(seq.getObjectAt(2));
				}
				break;
			case 3:
				date = ASN1GeneralizedTime.getInstance(seq.getObjectAt(1));
				other = OtherKeyAttribute.getInstance(seq.getObjectAt(2));
				break;
			default:
				throw new IllegalArgumentException("Invalid RecipientKeyIdentifier");
			}
		}

		/// <summary>
		/// Return a RecipientKeyIdentifier object from a tagged object.
		/// </summary>
		/// <param name="ato"> the tagged object holding the object we want. </param>
		/// <param name="isExplicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///          tagged object cannot be converted. </exception>
		public static RecipientKeyIdentifier getInstance(ASN1TaggedObject ato, bool isExplicit)
		{
			return getInstance(ASN1Sequence.getInstance(ato, isExplicit));
		}

		/// <summary>
		/// Return a RecipientKeyIdentifier object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="RecipientKeyIdentifier"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with RecipientKeyIdentifier structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static RecipientKeyIdentifier getInstance(object obj)
		{
			if (obj is RecipientKeyIdentifier)
			{
				return (RecipientKeyIdentifier)obj;
			}

			if (obj != null)
			{
				return new RecipientKeyIdentifier(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1OctetString getSubjectKeyIdentifier()
		{
			return subjectKeyIdentifier;
		}

		public virtual ASN1GeneralizedTime getDate()
		{
			return date;
		}

		public virtual OtherKeyAttribute getOtherKeyAttribute()
		{
			return other;
		}


		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(subjectKeyIdentifier);

			if (date != null)
			{
				v.add(date);
			}

			if (other != null)
			{
				v.add(other);
			}

			return new DERSequence(v);
		}
	}

}