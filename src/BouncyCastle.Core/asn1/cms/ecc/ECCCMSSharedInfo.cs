using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms.ecc
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// <pre>
	///     ECC-CMS-SharedInfo ::= SEQUENCE {
	///        keyInfo AlgorithmIdentifier,
	///        entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
	///        suppPubInfo [2] EXPLICIT OCTET STRING   }
	/// </pre>
	/// </summary>
	public class ECCCMSSharedInfo : ASN1Object
	{

		private readonly AlgorithmIdentifier keyInfo;
		private readonly byte[] entityUInfo;
		private readonly byte[] suppPubInfo;

		public ECCCMSSharedInfo(AlgorithmIdentifier keyInfo, byte[] entityUInfo, byte[] suppPubInfo)
		{
			this.keyInfo = keyInfo;
			this.entityUInfo = Arrays.clone(entityUInfo);
			this.suppPubInfo = Arrays.clone(suppPubInfo);
		}

		public ECCCMSSharedInfo(AlgorithmIdentifier keyInfo, byte[] suppPubInfo)
		{
			this.keyInfo = keyInfo;
			this.entityUInfo = null;
			this.suppPubInfo = Arrays.clone(suppPubInfo);
		}

		private ECCCMSSharedInfo(ASN1Sequence seq)
		{
			this.keyInfo = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));

			if (seq.size() == 2)
			{
				this.entityUInfo = null;
				this.suppPubInfo = ASN1OctetString.getInstance((ASN1TaggedObject)seq.getObjectAt(1), true).getOctets();
			}
			else
			{
				this.entityUInfo = ASN1OctetString.getInstance((ASN1TaggedObject)seq.getObjectAt(1), true).getOctets();
				this.suppPubInfo = ASN1OctetString.getInstance((ASN1TaggedObject)seq.getObjectAt(2), true).getOctets();
			}
		}

		/// <summary>
		/// Return an ECC-CMS-SharedInfo object from a tagged object.
		/// </summary>
		/// <param name="obj">      the tagged object holding the object we want. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///                 tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///                                  tagged object cannot be converted. </exception>
		public static ECCCMSSharedInfo getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static ECCCMSSharedInfo getInstance(object obj)
		{
			if (obj is ECCCMSSharedInfo)
			{
				return (ECCCMSSharedInfo)obj;
			}
			else if (obj != null)
			{
				return new ECCCMSSharedInfo(ASN1Sequence.getInstance(obj));
			}

			return null;
		}


		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(keyInfo);

			if (entityUInfo != null)
			{
				v.add(new DERTaggedObject(true, 0, new DEROctetString(entityUInfo)));
			}

			v.add(new DERTaggedObject(true, 2, new DEROctetString(suppPubInfo)));

			return new DERSequence(v);
		}
	}

}