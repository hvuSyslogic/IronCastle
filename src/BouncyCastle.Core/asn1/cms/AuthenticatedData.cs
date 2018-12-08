using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.cms
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-9.1">RFC 5652</a> section 9.1:
	/// The AuthenticatedData carries AuthAttributes and other data
	/// which define what really is being signed.
	/// <pre>
	/// AuthenticatedData ::= SEQUENCE {
	///       version CMSVersion,
	///       originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
	///       recipientInfos RecipientInfos,
	///       macAlgorithm MessageAuthenticationCodeAlgorithm,
	///       digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
	///       encapContentInfo EncapsulatedContentInfo,
	///       authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
	///       mac MessageAuthenticationCode,
	///       unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
	/// 
	/// AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
	/// 
	/// UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
	/// 
	/// MessageAuthenticationCode ::= OCTET STRING
	/// </pre>
	/// </summary>
	public class AuthenticatedData : ASN1Object
	{
		private ASN1Integer version;
		private OriginatorInfo originatorInfo;
		private ASN1Set recipientInfos;
		private AlgorithmIdentifier macAlgorithm;
		private AlgorithmIdentifier digestAlgorithm;
		private ContentInfo encapsulatedContentInfo;
		private ASN1Set authAttrs;
		private ASN1OctetString mac;
		private ASN1Set unauthAttrs;

		public AuthenticatedData(OriginatorInfo originatorInfo, ASN1Set recipientInfos, AlgorithmIdentifier macAlgorithm, AlgorithmIdentifier digestAlgorithm, ContentInfo encapsulatedContent, ASN1Set authAttrs, ASN1OctetString mac, ASN1Set unauthAttrs)
		{
			if (digestAlgorithm != null || authAttrs != null)
			{
				if (digestAlgorithm == null || authAttrs == null)
				{
					throw new IllegalArgumentException("digestAlgorithm and authAttrs must be set together");
				}
			}

			version = new ASN1Integer(calculateVersion(originatorInfo));

			this.originatorInfo = originatorInfo;
			this.macAlgorithm = macAlgorithm;
			this.digestAlgorithm = digestAlgorithm;
			this.recipientInfos = recipientInfos;
			this.encapsulatedContentInfo = encapsulatedContent;
			this.authAttrs = authAttrs;
			this.mac = mac;
			this.unauthAttrs = unauthAttrs;
		}

		private AuthenticatedData(ASN1Sequence seq)
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
			macAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(index++));

			tmp = seq.getObjectAt(index++);

			if (tmp is ASN1TaggedObject)
			{
				digestAlgorithm = AlgorithmIdentifier.getInstance((ASN1TaggedObject)tmp, false);
				tmp = seq.getObjectAt(index++);
			}

			encapsulatedContentInfo = ContentInfo.getInstance(tmp);

			tmp = seq.getObjectAt(index++);

			if (tmp is ASN1TaggedObject)
			{
				authAttrs = ASN1Set.getInstance((ASN1TaggedObject)tmp, false);
				tmp = seq.getObjectAt(index++);
			}

			mac = ASN1OctetString.getInstance(tmp);

			if (seq.size() > index)
			{
				unauthAttrs = ASN1Set.getInstance((ASN1TaggedObject)seq.getObjectAt(index), false);
			}
		}

		/// <summary>
		/// Return an AuthenticatedData object from a tagged object.
		/// </summary>
		/// <param name="obj">      the tagged object holding the object we want. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///                 tagged false otherwise. </param>
		/// <returns> a reference that can be assigned to AuthenticatedData (may be null) </returns>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///                                  tagged object cannot be converted. </exception>
		public static AuthenticatedData getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Return an AuthenticatedData object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="AuthenticatedData"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with AuthenticatedData structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> the object we want converted. </param>
		/// <returns> a reference that can be assigned to AuthenticatedData (may be null) </returns>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static AuthenticatedData getInstance(object obj)
		{
			if (obj is AuthenticatedData)
			{
				return (AuthenticatedData)obj;
			}
			else if (obj != null)
			{
				return new AuthenticatedData(ASN1Sequence.getInstance(obj));
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

		public virtual AlgorithmIdentifier getMacAlgorithm()
		{
			return macAlgorithm;
		}

		public virtual AlgorithmIdentifier getDigestAlgorithm()
		{
			return digestAlgorithm;
		}

		public virtual ContentInfo getEncapsulatedContentInfo()
		{
			return encapsulatedContentInfo;
		}

		public virtual ASN1Set getAuthAttrs()
		{
			return authAttrs;
		}

		public virtual ASN1OctetString getMac()
		{
			return mac;
		}

		public virtual ASN1Set getUnauthAttrs()
		{
			return unauthAttrs;
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
			v.add(macAlgorithm);

			if (digestAlgorithm != null)
			{
				v.add(new DERTaggedObject(false, 1, digestAlgorithm));
			}

			v.add(encapsulatedContentInfo);

			if (authAttrs != null)
			{
				v.add(new DERTaggedObject(false, 2, authAttrs));
			}

			v.add(mac);

			if (unauthAttrs != null)
			{
				v.add(new DERTaggedObject(false, 3, unauthAttrs));
			}

			return new BERSequence(v);
		}

		public static int calculateVersion(OriginatorInfo origInfo)
		{
			if (origInfo == null)
			{
				return 0;
			}
			else
			{
				int ver = 0;

				for (Enumeration e = origInfo.getCertificates().getObjects(); e.hasMoreElements();)
				{
					object obj = e.nextElement();

					if (obj is ASN1TaggedObject)
					{
						ASN1TaggedObject tag = (ASN1TaggedObject)obj;

						if (tag.getTagNo() == 2)
						{
							ver = 1;
						}
						else if (tag.getTagNo() == 3)
						{
							ver = 3;
							break;
						}
					}
				}

				if (origInfo.getCRLs() != null)
				{
					for (Enumeration e = origInfo.getCRLs().getObjects(); e.hasMoreElements();)
					{
						object obj = e.nextElement();

						if (obj is ASN1TaggedObject)
						{
							ASN1TaggedObject tag = (ASN1TaggedObject)obj;

							if (tag.getTagNo() == 1)
							{
								ver = 3;
								break;
							}
						}
					}
				}

				return ver;
			}
		}
	}

}