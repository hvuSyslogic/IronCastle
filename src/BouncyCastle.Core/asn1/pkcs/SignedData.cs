using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.pkcs
{


	/// <summary>
	/// a PKCS#7 signed data object.
	/// </summary>
	public class SignedData : ASN1Object, PKCSObjectIdentifiers
	{
		private ASN1Integer version;
		private ASN1Set digestAlgorithms;
		private ContentInfo contentInfo;
		private ASN1Set certificates;
		private ASN1Set crls;
		private ASN1Set signerInfos;

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

		public SignedData(ASN1Integer _version, ASN1Set _digestAlgorithms, ContentInfo _contentInfo, ASN1Set _certificates, ASN1Set _crls, ASN1Set _signerInfos)
		{
			version = _version;
			digestAlgorithms = _digestAlgorithms;
			contentInfo = _contentInfo;
			certificates = _certificates;
			crls = _crls;
			signerInfos = _signerInfos;
		}

		public SignedData(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			version = (ASN1Integer)e.nextElement();
			digestAlgorithms = ((ASN1Set)e.nextElement());
			contentInfo = ContentInfo.getInstance(e.nextElement());

			while (e.hasMoreElements())
			{
				ASN1Primitive o = (ASN1Primitive)e.nextElement();

				//
				// an interesting feature of SignedData is that there appear to be varying implementations...
				// for the moment we ignore anything which doesn't fit.
				//
				if (o is ASN1TaggedObject)
				{
					ASN1TaggedObject tagged = (ASN1TaggedObject)o;

					switch (tagged.getTagNo())
					{
					case 0:
						certificates = ASN1Set.getInstance(tagged, false);
						break;
					case 1:
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

		public virtual ContentInfo getContentInfo()
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
		/// <pre>
		///  SignedData ::= SEQUENCE {
		///      version Version,
		///      digestAlgorithms DigestAlgorithmIdentifiers,
		///      contentInfo ContentInfo,
		///      certificates
		///          [0] IMPLICIT ExtendedCertificatesAndCertificates
		///                   OPTIONAL,
		///      crls
		///          [1] IMPLICIT CertificateRevocationLists OPTIONAL,
		///      signerInfos SignerInfos }
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(version);
			v.add(digestAlgorithms);
			v.add(contentInfo);

			if (certificates != null)
			{
				v.add(new DERTaggedObject(false, 0, certificates));
			}

			if (crls != null)
			{
				v.add(new DERTaggedObject(false, 1, crls));
			}

			v.add(signerInfos);

			return new BERSequence(v);
		}
	}

}