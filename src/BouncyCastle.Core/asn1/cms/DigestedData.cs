using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-7">RFC 5652</a> DigestedData object.
	/// <pre>
	/// DigestedData ::= SEQUENCE {
	///       version CMSVersion,
	///       digestAlgorithm DigestAlgorithmIdentifier,
	///       encapContentInfo EncapsulatedContentInfo,
	///       digest Digest }
	/// </pre>
	/// </summary>
	public class DigestedData : ASN1Object
	{
		private ASN1Integer version;
		private AlgorithmIdentifier digestAlgorithm;
		private ContentInfo encapContentInfo;
		private ASN1OctetString digest;

		public DigestedData(AlgorithmIdentifier digestAlgorithm, ContentInfo encapContentInfo, byte[] digest)
		{
			this.version = new ASN1Integer(0);
			this.digestAlgorithm = digestAlgorithm;
			this.encapContentInfo = encapContentInfo;
			this.digest = new DEROctetString(digest);
		}

		private DigestedData(ASN1Sequence seq)
		{
			this.version = (ASN1Integer)seq.getObjectAt(0);
			this.digestAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
			this.encapContentInfo = ContentInfo.getInstance(seq.getObjectAt(2));
			this.digest = ASN1OctetString.getInstance(seq.getObjectAt(3));
		}

		/// <summary>
		/// Return a DigestedData object from a tagged object.
		/// </summary>
		/// <param name="ato"> the tagged object holding the object we want. </param>
		/// <param name="isExplicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///          tagged object cannot be converted. </exception>
		public static DigestedData getInstance(ASN1TaggedObject ato, bool isExplicit)
		{
			return getInstance(ASN1Sequence.getInstance(ato, isExplicit));
		}

		/// <summary>
		/// Return a DigestedData object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="DigestedData"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static DigestedData getInstance(object obj)
		{
			if (obj is DigestedData)
			{
				return (DigestedData)obj;
			}

			if (obj != null)
			{
				return new DigestedData(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1Integer getVersion()
		{
			return version;
		}

		public virtual AlgorithmIdentifier getDigestAlgorithm()
		{
			return digestAlgorithm;
		}

		public virtual ContentInfo getEncapContentInfo()
		{
			return encapContentInfo;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(version);
			v.add(digestAlgorithm);
			v.add(encapContentInfo);
			v.add(digest);

			return new BERSequence(v);
		}

		public virtual byte[] getDigest()
		{
			return digest.getOctets();
		}
	}

}