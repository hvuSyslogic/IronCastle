using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc3274">RFC 3274</a>: CMS Compressed Data.
	/// 
	/// <pre>
	/// CompressedData ::= SEQUENCE {
	///     version CMSVersion,
	///     compressionAlgorithm CompressionAlgorithmIdentifier,
	///     encapContentInfo EncapsulatedContentInfo
	/// }
	/// </pre>
	/// </summary>
	public class CompressedData : ASN1Object
	{
		private ASN1Integer version;
		private AlgorithmIdentifier compressionAlgorithm;
		private ContentInfo encapContentInfo;

		public CompressedData(AlgorithmIdentifier compressionAlgorithm, ContentInfo encapContentInfo)
		{
			this.version = new ASN1Integer(0);
			this.compressionAlgorithm = compressionAlgorithm;
			this.encapContentInfo = encapContentInfo;
		}

		private CompressedData(ASN1Sequence seq)
		{
			this.version = (ASN1Integer)seq.getObjectAt(0);
			this.compressionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
			this.encapContentInfo = ContentInfo.getInstance(seq.getObjectAt(2));
		}

		/// <summary>
		/// Return a CompressedData object from a tagged object.
		/// </summary>
		/// <param name="ato"> the tagged object holding the object we want. </param>
		/// <param name="isExplicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///          tagged object cannot be converted. </exception>
		public static CompressedData getInstance(ASN1TaggedObject ato, bool isExplicit)
		{
			return getInstance(ASN1Sequence.getInstance(ato, isExplicit));
		}

		/// <summary>
		/// Return a CompressedData object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="CompressedData"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with CompressedData structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static CompressedData getInstance(object obj)
		{
			if (obj is CompressedData)
			{
				return (CompressedData)obj;
			}

			if (obj != null)
			{
				return new CompressedData(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1Integer getVersion()
		{
			return version;
		}

		public virtual AlgorithmIdentifier getCompressionAlgorithmIdentifier()
		{
			return compressionAlgorithm;
		}

		public virtual ContentInfo getEncapContentInfo()
		{
			return encapContentInfo;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(version);
			v.add(compressionAlgorithm);
			v.add(encapContentInfo);

			return new BERSequence(v);
		}
	}

}