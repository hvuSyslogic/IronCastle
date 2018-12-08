using org.bouncycastle.asn1;

namespace org.bouncycastle.asn1.cms
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// Parse <seealso cref="AuthenticatedData"/> stream.
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
	public class AuthenticatedDataParser
	{
		private ASN1SequenceParser seq;
		private ASN1Integer version;
		private ASN1Encodable nextObject;
		private bool originatorInfoCalled;

		public AuthenticatedDataParser(ASN1SequenceParser seq)
		{
			this.seq = seq;
			this.version = ASN1Integer.getInstance(seq.readObject());
		}

		public virtual ASN1Integer getVersion()
		{
			return version;
		}

		public virtual OriginatorInfo getOriginatorInfo()
		{
			originatorInfoCalled = true;

			if (nextObject == null)
			{
				nextObject = seq.readObject();
			}

			if (nextObject is ASN1TaggedObjectParser && ((ASN1TaggedObjectParser)nextObject).getTagNo() == 0)
			{
				ASN1SequenceParser originatorInfo = (ASN1SequenceParser)((ASN1TaggedObjectParser)nextObject).getObjectParser(BERTags_Fields.SEQUENCE, false);
				nextObject = null;
				return OriginatorInfo.getInstance(originatorInfo.toASN1Primitive());
			}

			return null;
		}

		public virtual ASN1SetParser getRecipientInfos()
		{
			if (!originatorInfoCalled)
			{
				getOriginatorInfo();
			}

			if (nextObject == null)
			{
				nextObject = seq.readObject();
			}

			ASN1SetParser recipientInfos = (ASN1SetParser)nextObject;
			nextObject = null;
			return recipientInfos;
		}

		public virtual AlgorithmIdentifier getMacAlgorithm()
		{
			if (nextObject == null)
			{
				nextObject = seq.readObject();
			}

			if (nextObject != null)
			{
				ASN1SequenceParser o = (ASN1SequenceParser)nextObject;
				nextObject = null;
				return AlgorithmIdentifier.getInstance(o.toASN1Primitive());
			}

			return null;
		}

		public virtual AlgorithmIdentifier getDigestAlgorithm()
		{
			if (nextObject == null)
			{
				nextObject = seq.readObject();
			}

			if (nextObject is ASN1TaggedObjectParser)
			{
				AlgorithmIdentifier obj = AlgorithmIdentifier.getInstance((ASN1TaggedObject)nextObject.toASN1Primitive(), false);
				nextObject = null;
				return obj;
			}

			return null;
		}

		public virtual ContentInfoParser getEncapsulatedContentInfo()
		{
			if (nextObject == null)
			{
				nextObject = seq.readObject();
			}

			if (nextObject != null)
			{
				ASN1SequenceParser o = (ASN1SequenceParser)nextObject;
				nextObject = null;
				return new ContentInfoParser(o);
			}

			return null;
		}

		public virtual ASN1SetParser getAuthAttrs()
		{
			if (nextObject == null)
			{
				nextObject = seq.readObject();
			}

			if (nextObject is ASN1TaggedObjectParser)
			{
				ASN1Encodable o = nextObject;
				nextObject = null;
				return (ASN1SetParser)((ASN1TaggedObjectParser)o).getObjectParser(BERTags_Fields.SET, false);
			}

			return null;
		}

		public virtual ASN1OctetString getMac()
		{
			if (nextObject == null)
			{
				nextObject = seq.readObject();
			}

			ASN1Encodable o = nextObject;
			nextObject = null;

			return ASN1OctetString.getInstance(o.toASN1Primitive());
		}

		public virtual ASN1SetParser getUnauthAttrs()
		{
			if (nextObject == null)
			{
				nextObject = seq.readObject();
			}

			if (nextObject != null)
			{
				ASN1Encodable o = nextObject;
				nextObject = null;
				return (ASN1SetParser)((ASN1TaggedObjectParser)o).getObjectParser(BERTags_Fields.SET, false);
			}

			return null;
		}
	}

}