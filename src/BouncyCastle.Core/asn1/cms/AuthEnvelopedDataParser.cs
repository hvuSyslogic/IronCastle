using org.bouncycastle.asn1;

namespace org.bouncycastle.asn1.cms
{


	/// <summary>
	/// Parse <seealso cref="AuthEnvelopedData"/> input stream.
	/// 
	/// <pre>
	/// AuthEnvelopedData ::= SEQUENCE {
	///   version CMSVersion,
	///   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
	///   recipientInfos RecipientInfos,
	///   authEncryptedContentInfo EncryptedContentInfo,
	///   authAttrs [1] IMPLICIT AuthAttributes OPTIONAL,
	///   mac MessageAuthenticationCode,
	///   unauthAttrs [2] IMPLICIT UnauthAttributes OPTIONAL }
	/// </pre>
	/// </summary>
	public class AuthEnvelopedDataParser
	{
		private ASN1SequenceParser seq;
		private ASN1Integer version;
		private ASN1Encodable nextObject;
		private bool originatorInfoCalled;
		private EncryptedContentInfoParser authEncryptedContentInfoParser;

		public AuthEnvelopedDataParser(ASN1SequenceParser seq)
		{
			this.seq = seq;

			// "It MUST be set to 0."
			this.version = ASN1Integer.getInstance(seq.readObject());
			if (this.version.getValue().intValue() != 0)
			{
				throw new ASN1ParsingException("AuthEnvelopedData version number must be 0");
			}
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

		public virtual EncryptedContentInfoParser getAuthEncryptedContentInfo()
		{
			if (nextObject == null)
			{
				nextObject = seq.readObject();
			}

			if (nextObject != null)
			{
				ASN1SequenceParser o = (ASN1SequenceParser) nextObject;
				nextObject = null;
				authEncryptedContentInfoParser = new EncryptedContentInfoParser(o);
				return authEncryptedContentInfoParser;
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

			// "The authAttrs MUST be present if the content type carried in
			// EncryptedContentInfo is not id-data."
			if (!authEncryptedContentInfoParser.getContentType().Equals(CMSObjectIdentifiers_Fields.data))
			{
				throw new ASN1ParsingException("authAttrs must be present with non-data content");
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