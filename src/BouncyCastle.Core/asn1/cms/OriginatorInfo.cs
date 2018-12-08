using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-6.2.1">RFC 5652</a>: OriginatorInfo object.
	/// <pre>
	/// RFC 3369:
	/// 
	/// OriginatorInfo ::= SEQUENCE {
	///     certs [0] IMPLICIT CertificateSet OPTIONAL,
	///     crls  [1] IMPLICIT CertificateRevocationLists OPTIONAL 
	/// }
	/// CertificateRevocationLists ::= SET OF CertificateList (from X.509)
	/// 
	/// RFC 3582 / 5652:
	/// 
	/// OriginatorInfo ::= SEQUENCE {
	///     certs [0] IMPLICIT CertificateSet OPTIONAL,
	///     crls  [1] IMPLICIT RevocationInfoChoices OPTIONAL
	/// }
	/// RevocationInfoChoices ::= SET OF RevocationInfoChoice
	/// RevocationInfoChoice ::= CHOICE {
	///     crl CertificateList,
	///     other [1] IMPLICIT OtherRevocationInfoFormat }
	/// 
	/// OtherRevocationInfoFormat ::= SEQUENCE {
	///     otherRevInfoFormat OBJECT IDENTIFIER,
	///     otherRevInfo ANY DEFINED BY otherRevInfoFormat }
	/// </pre>
	/// <para>
	/// TODO: RevocationInfoChoices / RevocationInfoChoice.
	///       Constructor using CertificateSet, CertificationInfoChoices
	/// </para>
	/// </summary>
	public class OriginatorInfo : ASN1Object
	{
		private ASN1Set certs;
		private ASN1Set crls;

		public OriginatorInfo(ASN1Set certs, ASN1Set crls)
		{
			this.certs = certs;
			this.crls = crls;
		}

		private OriginatorInfo(ASN1Sequence seq)
		{
			switch (seq.size())
			{
			case 0: // empty
				break;
			case 1:
				ASN1TaggedObject o = (ASN1TaggedObject)seq.getObjectAt(0);
				switch (o.getTagNo())
				{
				case 0 :
					certs = ASN1Set.getInstance(o, false);
					break;
				case 1 :
					crls = ASN1Set.getInstance(o, false);
					break;
				default:
					throw new IllegalArgumentException("Bad tag in OriginatorInfo: " + o.getTagNo());
				}
				break;
			case 2:
				certs = ASN1Set.getInstance((ASN1TaggedObject)seq.getObjectAt(0), false);
				crls = ASN1Set.getInstance((ASN1TaggedObject)seq.getObjectAt(1), false);
				break;
			default:
				throw new IllegalArgumentException("OriginatorInfo too big");
			}
		}

		/// <summary>
		/// Return an OriginatorInfo object from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///          tagged object cannot be converted. </exception>
		public static OriginatorInfo getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Return an OriginatorInfo object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="OriginatorInfo"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with OriginatorInfo structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static OriginatorInfo getInstance(object obj)
		{
			if (obj is OriginatorInfo)
			{
				return (OriginatorInfo)obj;
			}
			else if (obj != null)
			{
				return new OriginatorInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1Set getCertificates()
		{
			return certs;
		}

		public virtual ASN1Set getCRLs()
		{
			return crls;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (certs != null)
			{
				v.add(new DERTaggedObject(false, 0, certs));
			}

			if (crls != null)
			{
				v.add(new DERTaggedObject(false, 1, crls));
			}

			return new DERSequence(v);
		}
	}

}