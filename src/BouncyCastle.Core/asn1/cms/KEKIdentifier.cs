using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-6.2.3">RFC 5652</a>:
	/// Content encryption key delivery mechanisms.
	/// <para>
	/// <pre>
	/// KEKIdentifier ::= SEQUENCE {
	///     keyIdentifier OCTET STRING,
	///     date GeneralizedTime OPTIONAL,
	///     other OtherKeyAttribute OPTIONAL 
	/// }
	/// </pre>
	/// </para>
	/// </summary>
	public class KEKIdentifier : ASN1Object
	{
		private ASN1OctetString keyIdentifier;
		private ASN1GeneralizedTime date;
		private OtherKeyAttribute other;

		public KEKIdentifier(byte[] keyIdentifier, ASN1GeneralizedTime date, OtherKeyAttribute other)
		{
			this.keyIdentifier = new DEROctetString(keyIdentifier);
			this.date = date;
			this.other = other;
		}

		private KEKIdentifier(ASN1Sequence seq)
		{
			keyIdentifier = (ASN1OctetString)seq.getObjectAt(0);

			switch (seq.size())
			{
			case 1:
				break;
			case 2:
				if (seq.getObjectAt(1) is ASN1GeneralizedTime)
				{
					date = (ASN1GeneralizedTime)seq.getObjectAt(1);
				}
				else
				{
					other = OtherKeyAttribute.getInstance(seq.getObjectAt(1));
				}
				break;
			case 3:
				date = (ASN1GeneralizedTime)seq.getObjectAt(1);
				other = OtherKeyAttribute.getInstance(seq.getObjectAt(2));
				break;
			default:
					throw new IllegalArgumentException("Invalid KEKIdentifier");
			}
		}

		/// <summary>
		/// Return a KEKIdentifier object from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///          tagged object cannot be converted. </exception>
		public static KEKIdentifier getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Return a KEKIdentifier object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="KEKIdentifier"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with KEKIdentifier structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static KEKIdentifier getInstance(object obj)
		{
			if (obj == null || obj is KEKIdentifier)
			{
				return (KEKIdentifier)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new KEKIdentifier((ASN1Sequence)obj);
			}

			throw new IllegalArgumentException("Invalid KEKIdentifier: " + obj.GetType().getName());
		}

		public virtual ASN1OctetString getKeyIdentifier()
		{
			return keyIdentifier;
		}

		public virtual ASN1GeneralizedTime getDate()
		{
			return date;
		}

		public virtual OtherKeyAttribute getOther()
		{
			return other;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(keyIdentifier);

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