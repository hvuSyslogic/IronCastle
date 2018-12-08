using System.IO;
using org.bouncycastle.asn1;
using org.bouncycastle.Port.Extensions;

namespace org.bouncycastle.asn1.cms
{


	/// <summary>
	/// Parser for <a href="http://tools.ietf.org/html/rfc5652#section-5.1">RFC 5652</a>: <seealso cref="SignedData"/> object.
	/// <para>
	/// <pre>
	/// SignedData ::= SEQUENCE {
	///     version CMSVersion,
	///     digestAlgorithms DigestAlgorithmIdentifiers,
	///     encapContentInfo EncapsulatedContentInfo,
	///     certificates [0] IMPLICIT CertificateSet OPTIONAL,
	///     crls [1] IMPLICIT CertificateRevocationLists OPTIONAL,
	///     signerInfos SignerInfos
	///   }
	/// </pre>
	/// </para>
	/// </summary>
	public class SignedDataParser
	{
		private ASN1SequenceParser _seq;
		private ASN1Integer _version;
		private object _nextObject;
		private bool _certsCalled;
		private bool _crlsCalled;

		public static SignedDataParser getInstance(object o)
		{
			if (o is ASN1Sequence)
			{
				return new SignedDataParser(((ASN1Sequence)o).parser());
			}
			if (o is ASN1SequenceParser)
			{
				return new SignedDataParser((ASN1SequenceParser)o);
			}

			throw new IOException("unknown object encountered: " + o.GetType().getName());
		}

		private SignedDataParser(ASN1SequenceParser seq)
		{
			this._seq = seq;
			this._version = (ASN1Integer)seq.readObject();
		}

		public virtual ASN1Integer getVersion()
		{
			return _version;
		}

		public virtual ASN1SetParser getDigestAlgorithms()
		{
			object o = _seq.readObject();

			if (o is ASN1Set)
			{
				return ((ASN1Set)o).parser();
			}

			return (ASN1SetParser)o;
		}

		public virtual ContentInfoParser getEncapContentInfo()
		{
			return new ContentInfoParser((ASN1SequenceParser)_seq.readObject());
		}

		public virtual ASN1SetParser getCertificates()
		{
			_certsCalled = true;
			_nextObject = _seq.readObject();

			if (_nextObject is ASN1TaggedObjectParser && ((ASN1TaggedObjectParser)_nextObject).getTagNo() == 0)
			{
				ASN1SetParser certs = (ASN1SetParser)((ASN1TaggedObjectParser)_nextObject).getObjectParser(BERTags_Fields.SET, false);
				_nextObject = null;

				return certs;
			}

			return null;
		}

		public virtual ASN1SetParser getCrls()
		{
			if (!_certsCalled)
			{
				throw new IOException("getCerts() has not been called.");
			}

			_crlsCalled = true;

			if (_nextObject == null)
			{
				_nextObject = _seq.readObject();
			}

			if (_nextObject is ASN1TaggedObjectParser && ((ASN1TaggedObjectParser)_nextObject).getTagNo() == 1)
			{
				ASN1SetParser crls = (ASN1SetParser)((ASN1TaggedObjectParser)_nextObject).getObjectParser(BERTags_Fields.SET, false);
				_nextObject = null;

				return crls;
			}

			return null;
		}

		public virtual ASN1SetParser getSignerInfos()
		{
			if (!_certsCalled || !_crlsCalled)
			{
				throw new IOException("getCerts() and/or getCrls() has not been called.");
			}

			if (_nextObject == null)
			{
				_nextObject = _seq.readObject();
			}

			return (ASN1SetParser)_nextObject;
		}
	}

}