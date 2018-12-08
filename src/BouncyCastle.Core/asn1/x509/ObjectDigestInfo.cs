using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{

	/// <summary>
	/// ObjectDigestInfo ASN.1 structure used in v2 attribute certificates.
	/// 
	/// <pre>
	/// 
	///    ObjectDigestInfo ::= SEQUENCE {
	///         digestedObjectType  ENUMERATED {
	///                 publicKey            (0),
	///                 publicKeyCert        (1),
	///                 otherObjectTypes     (2) },
	///                         -- otherObjectTypes MUST NOT
	///                         -- be used in this profile
	///         otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
	///         digestAlgorithm     AlgorithmIdentifier,
	///         objectDigest        BIT STRING
	///    }
	/// 
	/// </pre>
	/// 
	/// </summary>
	public class ObjectDigestInfo : ASN1Object
	{
		/// <summary>
		/// The public key is hashed.
		/// </summary>
		public const int publicKey = 0;

		/// <summary>
		/// The public key certificate is hashed.
		/// </summary>
		public const int publicKeyCert = 1;

		/// <summary>
		/// An other object is hashed.
		/// </summary>
		public const int otherObjectDigest = 2;

		internal ASN1Enumerated digestedObjectType;

		internal ASN1ObjectIdentifier otherObjectTypeID;

		internal AlgorithmIdentifier digestAlgorithm;

		internal DERBitString objectDigest;

		public static ObjectDigestInfo getInstance(object obj)
		{
			if (obj is ObjectDigestInfo)
			{
				return (ObjectDigestInfo)obj;
			}

			if (obj != null)
			{
				return new ObjectDigestInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static ObjectDigestInfo getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Constructor from given details.
		/// <para>
		/// If <code>digestedObjectType</code> is not <seealso cref="#publicKeyCert"/> or
		/// <seealso cref="#publicKey"/> <code>otherObjectTypeID</code> must be given,
		/// otherwise it is ignored.
		/// 
		/// </para>
		/// </summary>
		/// <param name="digestedObjectType"> The digest object type. </param>
		/// <param name="otherObjectTypeID"> The object type ID for
		///            <code>otherObjectDigest</code>. </param>
		/// <param name="digestAlgorithm"> The algorithm identifier for the hash. </param>
		/// <param name="objectDigest"> The hash value. </param>
		public ObjectDigestInfo(int digestedObjectType, ASN1ObjectIdentifier otherObjectTypeID, AlgorithmIdentifier digestAlgorithm, byte[] objectDigest)
		{
			this.digestedObjectType = new ASN1Enumerated(digestedObjectType);
			if (digestedObjectType == otherObjectDigest)
			{
				this.otherObjectTypeID = otherObjectTypeID;
			}

			this.digestAlgorithm = digestAlgorithm;
			this.objectDigest = new DERBitString(objectDigest);
		}

		private ObjectDigestInfo(ASN1Sequence seq)
		{
			if (seq.size() > 4 || seq.size() < 3)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			digestedObjectType = ASN1Enumerated.getInstance(seq.getObjectAt(0));

			int offset = 0;

			if (seq.size() == 4)
			{
				otherObjectTypeID = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(1));
				offset++;
			}

			digestAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1 + offset));

			objectDigest = DERBitString.getInstance(seq.getObjectAt(2 + offset));
		}

		public virtual ASN1Enumerated getDigestedObjectType()
		{
			return digestedObjectType;
		}

		public virtual ASN1ObjectIdentifier getOtherObjectTypeID()
		{
			return otherObjectTypeID;
		}

		public virtual AlgorithmIdentifier getDigestAlgorithm()
		{
			return digestAlgorithm;
		}

		public virtual DERBitString getObjectDigest()
		{
			return objectDigest;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// 
		/// <pre>
		/// 
		///    ObjectDigestInfo ::= SEQUENCE {
		///         digestedObjectType  ENUMERATED {
		///                 publicKey            (0),
		///                 publicKeyCert        (1),
		///                 otherObjectTypes     (2) },
		///                         -- otherObjectTypes MUST NOT
		///                         -- be used in this profile
		///         otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
		///         digestAlgorithm     AlgorithmIdentifier,
		///         objectDigest        BIT STRING
		///    }
		/// 
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(digestedObjectType);

			if (otherObjectTypeID != null)
			{
				v.add(otherObjectTypeID);
			}

			v.add(digestAlgorithm);
			v.add(objectDigest);

			return new DERSequence(v);
		}
	}

}