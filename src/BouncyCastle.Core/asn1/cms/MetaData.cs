using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5544">RFC 5544</a>:
	/// Binding Documents with Time-Stamps; MetaData object.
	/// <para>
	/// <pre>
	/// MetaData ::= SEQUENCE {
	///   hashProtected        BOOLEAN,
	///   fileName             UTF8String OPTIONAL,
	///   mediaType            IA5String OPTIONAL,
	///   otherMetaData        Attributes OPTIONAL
	/// }
	/// </pre>
	/// </para>
	/// </summary>
	public class MetaData : ASN1Object
	{
		private ASN1Boolean hashProtected;
		private DERUTF8String fileName;
		private DERIA5String mediaType;
		private Attributes otherMetaData;

		public MetaData(ASN1Boolean hashProtected, DERUTF8String fileName, DERIA5String mediaType, Attributes otherMetaData)
		{
			this.hashProtected = hashProtected;
			this.fileName = fileName;
			this.mediaType = mediaType;
			this.otherMetaData = otherMetaData;
		}

		private MetaData(ASN1Sequence seq)
		{
			this.hashProtected = ASN1Boolean.getInstance(seq.getObjectAt(0));

			int index = 1;

			if (index < seq.size() && seq.getObjectAt(index) is DERUTF8String)
			{
				this.fileName = DERUTF8String.getInstance(seq.getObjectAt(index++));
			}
			if (index < seq.size() && seq.getObjectAt(index) is DERIA5String)
			{
				this.mediaType = DERIA5String.getInstance(seq.getObjectAt(index++));
			}
			if (index < seq.size())
			{
				this.otherMetaData = Attributes.getInstance(seq.getObjectAt(index++));
			}
		}

		/// <summary>
		/// Return a MetaData object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="MetaData"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with MetaData structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static MetaData getInstance(object obj)
		{
			if (obj is MetaData)
			{
				return (MetaData)obj;
			}
			else if (obj != null)
			{
				return new MetaData(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(hashProtected);

			if (fileName != null)
			{
				v.add(fileName);
			}

			if (mediaType != null)
			{
				v.add(mediaType);
			}

			if (otherMetaData != null)
			{
				v.add(otherMetaData);
			}

			return new DERSequence(v);
		}

		public virtual bool isHashProtected()
		{
			return hashProtected.isTrue();
		}

		public virtual DERUTF8String getFileName()
		{
			return this.fileName;
		}

		public virtual DERIA5String getMediaType()
		{
			return this.mediaType;
		}

		public virtual Attributes getOtherMetaData()
		{
			return otherMetaData;
		}
	}

}