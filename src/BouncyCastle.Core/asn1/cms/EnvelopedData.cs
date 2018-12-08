using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.cms
{


	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-6.1">RFC 5652</a> EnvelopedData object.
	/// <pre>
	/// EnvelopedData ::= SEQUENCE {
	///     version CMSVersion,
	///     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
	///     recipientInfos RecipientInfos,
	///     encryptedContentInfo EncryptedContentInfo,
	///     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL 
	/// }
	/// </pre>
	/// </summary>
	public class EnvelopedData : ASN1Object
	{
		private ASN1Integer version;
		private OriginatorInfo originatorInfo;
		private ASN1Set recipientInfos;
		private EncryptedContentInfo encryptedContentInfo;
		private ASN1Set unprotectedAttrs;

		public EnvelopedData(OriginatorInfo originatorInfo, ASN1Set recipientInfos, EncryptedContentInfo encryptedContentInfo, ASN1Set unprotectedAttrs)
		{
			version = new ASN1Integer(calculateVersion(originatorInfo, recipientInfos, unprotectedAttrs));

			this.originatorInfo = originatorInfo;
			this.recipientInfos = recipientInfos;
			this.encryptedContentInfo = encryptedContentInfo;
			this.unprotectedAttrs = unprotectedAttrs;
		}

		public EnvelopedData(OriginatorInfo originatorInfo, ASN1Set recipientInfos, EncryptedContentInfo encryptedContentInfo, Attributes unprotectedAttrs)
		{
			version = new ASN1Integer(calculateVersion(originatorInfo, recipientInfos, ASN1Set.getInstance(unprotectedAttrs)));

			this.originatorInfo = originatorInfo;
			this.recipientInfos = recipientInfos;
			this.encryptedContentInfo = encryptedContentInfo;
			this.unprotectedAttrs = ASN1Set.getInstance(unprotectedAttrs);
		}

		/// @deprecated use getInstance() 
		public EnvelopedData(ASN1Sequence seq)
		{
			int index = 0;

			version = (ASN1Integer)seq.getObjectAt(index++);

			object tmp = seq.getObjectAt(index++);

			if (tmp is ASN1TaggedObject)
			{
				originatorInfo = OriginatorInfo.getInstance((ASN1TaggedObject)tmp, false);
				tmp = seq.getObjectAt(index++);
			}

			recipientInfos = ASN1Set.getInstance(tmp);

			encryptedContentInfo = EncryptedContentInfo.getInstance(seq.getObjectAt(index++));

			if (seq.size() > index)
			{
				unprotectedAttrs = ASN1Set.getInstance((ASN1TaggedObject)seq.getObjectAt(index), false);
			}
		}

		/// <summary>
		/// Return an EnvelopedData object from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///          tagged object cannot be converted. </exception>
		public static EnvelopedData getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Return an EnvelopedData object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="EnvelopedData"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with EnvelopedData structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static EnvelopedData getInstance(object obj)
		{
			if (obj is EnvelopedData)
			{
				return (EnvelopedData)obj;
			}

			if (obj != null)
			{
				return new EnvelopedData(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public virtual ASN1Integer getVersion()
		{
			return version;
		}

		public virtual OriginatorInfo getOriginatorInfo()
		{
			return originatorInfo;
		}

		public virtual ASN1Set getRecipientInfos()
		{
			return recipientInfos;
		}

		public virtual EncryptedContentInfo getEncryptedContentInfo()
		{
			return encryptedContentInfo;
		}

		public virtual ASN1Set getUnprotectedAttrs()
		{
			return unprotectedAttrs;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(version);

			if (originatorInfo != null)
			{
				v.add(new DERTaggedObject(false, 0, originatorInfo));
			}

			v.add(recipientInfos);
			v.add(encryptedContentInfo);

			if (unprotectedAttrs != null)
			{
				v.add(new DERTaggedObject(false, 1, unprotectedAttrs));
			}

			return new BERSequence(v);
		}

		public static int calculateVersion(OriginatorInfo originatorInfo, ASN1Set recipientInfos, ASN1Set unprotectedAttrs)
		{
			int version;

			if (originatorInfo != null || unprotectedAttrs != null)
			{
				version = 2;
			}
			else
			{
				version = 0;

				Enumeration e = recipientInfos.getObjects();

				while (e.hasMoreElements())
				{
					RecipientInfo ri = RecipientInfo.getInstance(e.nextElement());

					if (ri.getVersion().getValue().intValue() != version)
					{
						version = 2;
						break;
					}
				}
			}

			return version;
		}
	}

}