using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.cms
{


	/// <summary>
	/// <a href="http://tools.ietf.org/html/rfc5652#section-5.1">RFC 5652</a>:
	/// <para>
	/// A signed data object containing multitude of <seealso cref="SignerInfo"/>s.
	/// <pre>
	/// SignedData ::= SEQUENCE {
	///     version CMSVersion,
	///     digestAlgorithms DigestAlgorithmIdentifiers,
	///     encapContentInfo EncapsulatedContentInfo,
	///     certificates [0] IMPLICIT CertificateSet OPTIONAL,
	///     crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
	///     signerInfos SignerInfos
	///   }
	/// 
	/// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
	/// 
	/// SignerInfos ::= SET OF SignerInfo
	/// </pre>
	/// </para>
	/// <para>
	/// The version calculation uses following ruleset from RFC 5652 section 5.1:
	/// <pre>
	/// IF ((certificates is present) AND
	///    (any certificates with a type of other are present)) OR
	///    ((crls is present) AND
	///    (any crls with a type of other are present))
	/// THEN version MUST be 5
	/// ELSE
	///    IF (certificates is present) AND
	///       (any version 2 attribute certificates are present)
	///    THEN version MUST be 4
	///    ELSE
	///       IF ((certificates is present) AND
	///          (any version 1 attribute certificates are present)) OR
	///          (any SignerInfo structures are version 3) OR
	///          (encapContentInfo eContentType is other than id-data)
	///       THEN version MUST be 3
	///       ELSE version MUST be 1
	/// </pre>
	/// </para>
	/// <para>
	/// </para>
	/// </summary>
	public class SignedData : ASN1Object
	{
		private static readonly ASN1Integer VERSION_1 = new ASN1Integer(1);
		private static readonly ASN1Integer VERSION_3 = new ASN1Integer(3);
		private static readonly ASN1Integer VERSION_4 = new ASN1Integer(4);
		private static readonly ASN1Integer VERSION_5 = new ASN1Integer(5);

		private ASN1Integer version;
		private ASN1Set digestAlgorithms;
		private ContentInfo contentInfo;
		private ASN1Set certificates;
		private ASN1Set crls;
		private ASN1Set signerInfos;
		private bool certsBer;
		private bool crlsBer;

		/// <summary>
		/// Return a SignedData object from the given object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="SignedData"/> object
		/// <li> <seealso cref="org.bouncycastle.asn1.ASN1Sequence#getInstance(java.lang.Object) ASN1Sequence"/> input formats with SignedData structure inside
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <param name="o"> the object we want converted. </param>
		/// <returns> a reference that can be assigned to SignedData (may be null) </returns>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static SignedData getInstance(object o)
		{
			if (o is SignedData)
			{
				return (SignedData)o;
			}
			else if (o != null)
			{
				return new SignedData(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public SignedData(ASN1Set digestAlgorithms, ContentInfo contentInfo, ASN1Set certificates, ASN1Set crls, ASN1Set signerInfos)
		{
			this.version = calculateVersion(contentInfo.getContentType(), certificates, crls, signerInfos);
			this.digestAlgorithms = digestAlgorithms;
			this.contentInfo = contentInfo;
			this.certificates = certificates;
			this.crls = crls;
			this.signerInfos = signerInfos;
			this.crlsBer = crls is BERSet;
			this.certsBer = certificates is BERSet;
		}


		private ASN1Integer calculateVersion(ASN1ObjectIdentifier contentOid, ASN1Set certs, ASN1Set crls, ASN1Set signerInfs)
		{
			bool otherCert = false;
			bool otherCrl = false;
			bool attrCertV1Found = false;
			bool attrCertV2Found = false;

			if (certs != null)
			{
				for (Enumeration en = certs.getObjects(); en.hasMoreElements();)
				{
					object obj = en.nextElement();
					if (obj is ASN1TaggedObject)
					{
						ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(obj);

						if (tagged.getTagNo() == 1)
						{
							attrCertV1Found = true;
						}
						else if (tagged.getTagNo() == 2)
						{
							attrCertV2Found = true;
						}
						else if (tagged.getTagNo() == 3)
						{
							otherCert = true;
						}
					}
				}
			}

			if (otherCert)
			{
				return new ASN1Integer(5);
			}

			if (crls != null) // no need to check if otherCert is true
			{
				for (Enumeration en = crls.getObjects(); en.hasMoreElements();)
				{
					object obj = en.nextElement();
					if (obj is ASN1TaggedObject)
					{
						otherCrl = true;
					}
				}
			}

			if (otherCrl)
			{
				return VERSION_5;
			}

			if (attrCertV2Found)
			{
				return VERSION_4;
			}

			if (attrCertV1Found)
			{
				return VERSION_3;
			}

			if (checkForVersion3(signerInfs))
			{
				return VERSION_3;
			}

			if (!CMSObjectIdentifiers_Fields.data.Equals(contentOid))
			{
				return VERSION_3;
			}

			return VERSION_1;
		}

		private bool checkForVersion3(ASN1Set signerInfs)
		{
			for (Enumeration e = signerInfs.getObjects(); e.hasMoreElements();)
			{
				SignerInfo s = SignerInfo.getInstance(e.nextElement());

				if (s.getVersion().getValue().intValue() == 3)
				{
					return true;
				}
			}

			return false;
		}

		private SignedData(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			version = ASN1Integer.getInstance(e.nextElement());
			digestAlgorithms = ((ASN1Set)e.nextElement());
			contentInfo = ContentInfo.getInstance(e.nextElement());

			while (e.hasMoreElements())
			{
				ASN1Primitive o = (ASN1Primitive)e.nextElement();

				//
				// an interesting feature of SignedData is that there appear
				// to be varying implementations...
				// for the moment we ignore anything which doesn't fit.
				//
				if (o is ASN1TaggedObject)
				{
					ASN1TaggedObject tagged = (ASN1TaggedObject)o;

					switch (tagged.getTagNo())
					{
					case 0:
						certsBer = tagged is BERTaggedObject;
						certificates = ASN1Set.getInstance(tagged, false);
						break;
					case 1:
						crlsBer = tagged is BERTaggedObject;
						crls = ASN1Set.getInstance(tagged, false);
						break;
					default:
						throw new IllegalArgumentException("unknown tag value " + tagged.getTagNo());
					}
				}
				else
				{
					signerInfos = (ASN1Set)o;
				}
			}
		}

		public virtual ASN1Integer getVersion()
		{
			return version;
		}

		public virtual ASN1Set getDigestAlgorithms()
		{
			return digestAlgorithms;
		}

		public virtual ContentInfo getEncapContentInfo()
		{
			return contentInfo;
		}

		public virtual ASN1Set getCertificates()
		{
			return certificates;
		}

		public virtual ASN1Set getCRLs()
		{
			return crls;
		}

		public virtual ASN1Set getSignerInfos()
		{
			return signerInfos;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(version);
			v.add(digestAlgorithms);
			v.add(contentInfo);

			if (certificates != null)
			{
				if (certsBer)
				{
					v.add(new BERTaggedObject(false, 0, certificates));
				}
				else
				{
					v.add(new DERTaggedObject(false, 0, certificates));
				}
			}

			if (crls != null)
			{
				if (crlsBer)
				{
					v.add(new BERTaggedObject(false, 1, crls));
				}
				else
				{
					v.add(new DERTaggedObject(false, 1, crls));
				}
			}

			v.add(signerInfos);

			return new BERSequence(v);
		}
	}

}