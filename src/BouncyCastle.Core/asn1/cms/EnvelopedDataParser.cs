using org.bouncycastle.asn1;

namespace org.bouncycastle.asn1.cms
{


	/// <summary>
	/// Parser of <a href="http://tools.ietf.org/html/rfc5652#section-6.1">RFC 5652</a> <seealso cref="EnvelopedData"/> object.
	/// <para>
	/// <pre>
	/// EnvelopedData ::= SEQUENCE {
	///     version CMSVersion,
	///     originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
	///     recipientInfos RecipientInfos,
	///     encryptedContentInfo EncryptedContentInfo,
	///     unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL 
	/// }
	/// </pre>
	/// </para>
	/// </summary>
	public class EnvelopedDataParser
	{
		private ASN1SequenceParser _seq;
		private ASN1Integer _version;
		private ASN1Encodable _nextObject;
		private bool _originatorInfoCalled;

		public EnvelopedDataParser(ASN1SequenceParser seq)
		{
			this._seq = seq;
			this._version = ASN1Integer.getInstance(seq.readObject());
		}

		public virtual ASN1Integer getVersion()
		{
			return _version;
		}

		public virtual OriginatorInfo getOriginatorInfo()
		{
			_originatorInfoCalled = true;

			if (_nextObject == null)
			{
				_nextObject = _seq.readObject();
			}

			if (_nextObject is ASN1TaggedObjectParser && ((ASN1TaggedObjectParser)_nextObject).getTagNo() == 0)
			{
				ASN1SequenceParser originatorInfo = (ASN1SequenceParser)((ASN1TaggedObjectParser)_nextObject).getObjectParser(BERTags_Fields.SEQUENCE, false);
				_nextObject = null;
				return OriginatorInfo.getInstance(originatorInfo.toASN1Primitive());
			}

			return null;
		}

		public virtual ASN1SetParser getRecipientInfos()
		{
			if (!_originatorInfoCalled)
			{
				getOriginatorInfo();
			}

			if (_nextObject == null)
			{
				_nextObject = _seq.readObject();
			}

			ASN1SetParser recipientInfos = (ASN1SetParser)_nextObject;
			_nextObject = null;
			return recipientInfos;
		}

		public virtual EncryptedContentInfoParser getEncryptedContentInfo()
		{
			if (_nextObject == null)
			{
				_nextObject = _seq.readObject();
			}


			if (_nextObject != null)
			{
				ASN1SequenceParser o = (ASN1SequenceParser) _nextObject;
				_nextObject = null;
				return new EncryptedContentInfoParser(o);
			}

			return null;
		}

		public virtual ASN1SetParser getUnprotectedAttrs()
		{
			if (_nextObject == null)
			{
				_nextObject = _seq.readObject();
			}


			if (_nextObject != null)
			{
				ASN1Encodable o = _nextObject;
				_nextObject = null;
				return (ASN1SetParser)((ASN1TaggedObjectParser)o).getObjectParser(BERTags_Fields.SET, false);
			}

			return null;
		}
	}

}