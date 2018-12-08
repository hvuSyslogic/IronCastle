using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-6.2.2">RFC 5652</a>:
	/// Content encryption key delivery mechanisms.
	/// <para>
	/// <pre>
	/// OriginatorPublicKey ::= SEQUENCE {
	///     algorithm AlgorithmIdentifier,
	///     publicKey BIT STRING 
	/// }
	/// </pre>
	/// </para>
	/// </summary>
	public class OriginatorPublicKey : ASN1Object
	{
		private AlgorithmIdentifier algorithm;
		private DERBitString publicKey;

		public OriginatorPublicKey(AlgorithmIdentifier algorithm, byte[] publicKey)
		{
			this.algorithm = algorithm;
			this.publicKey = new DERBitString(publicKey);
		}

		/// @deprecated use getInstance() 
		public OriginatorPublicKey(ASN1Sequence seq)
		{
			algorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
			publicKey = (DERBitString)seq.getObjectAt(1);
		}

		/// <summary>
		/// Return an OriginatorPublicKey object from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///          tagged object cannot be converted. </exception>
		public static OriginatorPublicKey getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Return an OriginatorPublicKey object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="OriginatorPublicKey"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with OriginatorPublicKey structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static OriginatorPublicKey getInstance(object obj)
		{
			if (obj is OriginatorPublicKey)
			{
				return (OriginatorPublicKey)obj;
			}

			if (obj != null)
			{
				return new OriginatorPublicKey(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual AlgorithmIdentifier getAlgorithm()
		{
			return algorithm;
		}

		public virtual DERBitString getPublicKey()
		{
			return publicKey;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(algorithm);
			v.add(publicKey);

			return new DERSequence(v);
		}
	}

}