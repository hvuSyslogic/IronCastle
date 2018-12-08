using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-8">RFC 5652</a> EncryptedData object.
	/// <para>
	/// <pre>
	/// EncryptedData ::= SEQUENCE {
	///     version CMSVersion,
	///     encryptedContentInfo EncryptedContentInfo,
	///     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
	/// </pre>
	/// </para>
	/// </summary>
	public class EncryptedData : ASN1Object
	{
		private ASN1Integer version;
		private EncryptedContentInfo encryptedContentInfo;
		private ASN1Set unprotectedAttrs;

		/// <summary>
		/// Return an EncryptedData object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="EncryptedData"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="o"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static EncryptedData getInstance(object o)
		{
			if (o is EncryptedData)
			{
				return (EncryptedData)o;
			}

			if (o != null)
			{
				return new EncryptedData(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public EncryptedData(EncryptedContentInfo encInfo) : this(encInfo, null)
		{
		}

		public EncryptedData(EncryptedContentInfo encInfo, ASN1Set unprotectedAttrs)
		{
			this.version = new ASN1Integer((unprotectedAttrs == null) ? 0 : 2);
			this.encryptedContentInfo = encInfo;
			this.unprotectedAttrs = unprotectedAttrs;
		}

		private EncryptedData(ASN1Sequence seq)
		{
			this.version = ASN1Integer.getInstance(seq.getObjectAt(0));
			this.encryptedContentInfo = EncryptedContentInfo.getInstance(seq.getObjectAt(1));

			if (seq.size() == 3)
			{
				this.unprotectedAttrs = ASN1Set.getInstance((ASN1TaggedObject)seq.getObjectAt(2), false);
			}
		}

		public virtual ASN1Integer getVersion()
		{
			return version;
		}

		public virtual EncryptedContentInfo getEncryptedContentInfo()
		{
			return encryptedContentInfo;
		}

		public virtual ASN1Set getUnprotectedAttrs()
		{
			return unprotectedAttrs;
		}

		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(version);
			v.add(encryptedContentInfo);
			if (unprotectedAttrs != null)
			{
				v.add(new BERTaggedObject(false, 1, unprotectedAttrs));
			}

			return new BERSequence(v);
		}
	}

}