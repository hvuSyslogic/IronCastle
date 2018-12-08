﻿using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cms
{

	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5083">RFC 5083</a>:
	/// 
	/// CMS AuthEnveloped Data object.
	/// <para>
	/// ASN.1:
	/// <pre>
	/// id-ct-authEnvelopedData OBJECT IDENTIFIER ::= { iso(1)
	///       member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9)
	///       smime(16) ct(1) 23 }
	/// 
	/// AuthEnvelopedData ::= SEQUENCE {
	///       version CMSVersion,
	///       originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
	///       recipientInfos RecipientInfos,
	///       authEncryptedContentInfo EncryptedContentInfo,
	///       authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
	///       mac MessageAuthenticationCode,
	///       unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }
	/// </pre>
	/// </para>
	/// </summary>
	public class AuthEnvelopedData : ASN1Object
	{
		private ASN1Integer version;
		private OriginatorInfo originatorInfo;
		private ASN1Set recipientInfos;
		private EncryptedContentInfo authEncryptedContentInfo;
		private ASN1Set authAttrs;
		private ASN1OctetString mac;
		private ASN1Set unauthAttrs;

		public AuthEnvelopedData(OriginatorInfo originatorInfo, ASN1Set recipientInfos, EncryptedContentInfo authEncryptedContentInfo, ASN1Set authAttrs, ASN1OctetString mac, ASN1Set unauthAttrs)
		{
			// "It MUST be set to 0."
			this.version = new ASN1Integer(0);

			this.originatorInfo = originatorInfo;

			// "There MUST be at least one element in the collection."
			this.recipientInfos = recipientInfos;
			if (this.recipientInfos.size() == 0)
			{
				throw new IllegalArgumentException("AuthEnvelopedData requires at least 1 RecipientInfo");
			}

			this.authEncryptedContentInfo = authEncryptedContentInfo;

			// "The authAttrs MUST be present if the content type carried in
			// EncryptedContentInfo is not id-data."
			this.authAttrs = authAttrs;
			if (!authEncryptedContentInfo.getContentType().Equals(CMSObjectIdentifiers_Fields.data))
			{
				if (authAttrs == null || authAttrs.size() == 0)
				{
					throw new IllegalArgumentException("authAttrs must be present with non-data content");
				}
			}

			this.mac = mac;

			this.unauthAttrs = unauthAttrs;
		}

		/// <summary>
		/// Constructs AuthEnvelopedData by parsing supplied ASN1Sequence
		/// <para>
		/// </para>
		/// </summary>
		/// <param name="seq"> An ASN1Sequence with AuthEnvelopedData </param>
		private AuthEnvelopedData(ASN1Sequence seq)
		{
			int index = 0;

			// "It MUST be set to 0."
			ASN1Primitive tmp = seq.getObjectAt(index++).toASN1Primitive();
			version = (ASN1Integer)tmp;
			if (this.version.getValue().intValue() != 0)
			{
				throw new IllegalArgumentException("AuthEnvelopedData version number must be 0");
			}

			tmp = seq.getObjectAt(index++).toASN1Primitive();
			if (tmp is ASN1TaggedObject)
			{
				originatorInfo = OriginatorInfo.getInstance((ASN1TaggedObject)tmp, false);
				tmp = seq.getObjectAt(index++).toASN1Primitive();
			}

			// "There MUST be at least one element in the collection."
			recipientInfos = ASN1Set.getInstance(tmp);
			if (this.recipientInfos.size() == 0)
			{
				throw new IllegalArgumentException("AuthEnvelopedData requires at least 1 RecipientInfo");
			}

			tmp = seq.getObjectAt(index++).toASN1Primitive();
			authEncryptedContentInfo = EncryptedContentInfo.getInstance(tmp);

			tmp = seq.getObjectAt(index++).toASN1Primitive();
			if (tmp is ASN1TaggedObject)
			{
				authAttrs = ASN1Set.getInstance((ASN1TaggedObject)tmp, false);
				tmp = seq.getObjectAt(index++).toASN1Primitive();
			}
			else
			{
				// "The authAttrs MUST be present if the content type carried in
				// EncryptedContentInfo is not id-data."
				if (!authEncryptedContentInfo.getContentType().Equals(CMSObjectIdentifiers_Fields.data))
				{
					if (authAttrs == null || authAttrs.size() == 0)
					{
						throw new IllegalArgumentException("authAttrs must be present with non-data content");
					}
				}
			}

			mac = ASN1OctetString.getInstance(tmp);

			if (seq.size() > index)
			{
				tmp = seq.getObjectAt(index).toASN1Primitive();
				unauthAttrs = ASN1Set.getInstance((ASN1TaggedObject)tmp, false);
			}
		}

		/// <summary>
		/// Return an AuthEnvelopedData object from a tagged object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats
		/// </ul>
		/// 
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj">      the tagged object holding the object we want. </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///                 tagged false otherwise. </param>
		/// <returns> a reference that can be assigned to AuthEnvelopedData (may be null) </returns>
		/// <exception cref="IllegalArgumentException"> if the object held by the
		///                                  tagged object cannot be converted. </exception>
		public static AuthEnvelopedData getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Return an AuthEnvelopedData object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="AuthEnvelopedData"/> object
		/// <li> <seealso cref="ASN1Sequence"/> input formats with AuthEnvelopedData structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="obj"> The object we want converted. </param>
		/// <returns> a reference that can be assigned to AuthEnvelopedData (may be null) </returns>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted, or was null. </exception>
		public static AuthEnvelopedData getInstance(object obj)
		{
			if (obj == null || obj is AuthEnvelopedData)
			{
				return (AuthEnvelopedData)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new AuthEnvelopedData((ASN1Sequence)obj);
			}

			throw new IllegalArgumentException("Invalid AuthEnvelopedData: " + obj.GetType().getName());
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

		public virtual EncryptedContentInfo getAuthEncryptedContentInfo()
		{
			return authEncryptedContentInfo;
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
			v.add(authEncryptedContentInfo);

			// "authAttrs optionally contains the authenticated attributes."
			if (authAttrs != null)
			{
				// "AuthAttributes MUST be DER encoded, even if the rest of the
				// AuthEnvelopedData structure is BER encoded."
				v.add(new DERTaggedObject(false, 1, authAttrs));
			}

			v.add(mac);

			// "unauthAttrs optionally contains the unauthenticated attributes."
			if (unauthAttrs != null)
			{
				v.add(new DERTaggedObject(false, 2, unauthAttrs));
			}

			return new BERSequence(v);
		}
	}

}