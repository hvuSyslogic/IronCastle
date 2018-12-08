namespace org.bouncycastle.tsp
{

	using ASN1Boolean = org.bouncycastle.asn1.ASN1Boolean;
	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using MessageImprint = org.bouncycastle.asn1.tsp.MessageImprint;
	using TimeStampReq = org.bouncycastle.asn1.tsp.TimeStampReq;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using ExtensionsGenerator = org.bouncycastle.asn1.x509.ExtensionsGenerator;

	/// <summary>
	/// Generator for RFC 3161 Time Stamp Request objects.
	/// </summary>
	public class TimeStampRequestGenerator
	{
		private ASN1ObjectIdentifier reqPolicy;

		private ASN1Boolean certReq;
		private ExtensionsGenerator extGenerator = new ExtensionsGenerator();

		public TimeStampRequestGenerator()
		{
		}

		/// @deprecated use method taking ASN1ObjectIdentifier 
		/// <param name="reqPolicy"> </param>
		public virtual void setReqPolicy(string reqPolicy)
		{
			this.reqPolicy = new ASN1ObjectIdentifier(reqPolicy);
		}

		public virtual void setReqPolicy(ASN1ObjectIdentifier reqPolicy)
		{
			this.reqPolicy = reqPolicy;
		}

		public virtual void setCertReq(bool certReq)
		{
			this.certReq = ASN1Boolean.getInstance(certReq);
		}

		/// <summary>
		/// add a given extension field for the standard extensions tag (tag 3) </summary>
		/// <exception cref="IOException"> </exception>
		/// @deprecated use method taking ASN1ObjectIdentifier 
		public virtual void addExtension(string OID, bool critical, ASN1Encodable value)
		{
			this.addExtension(OID, critical, value.toASN1Primitive().getEncoded());
		}

		/// <summary>
		/// add a given extension field for the standard extensions tag
		/// The value parameter becomes the contents of the octet string associated
		/// with the extension. </summary>
		/// @deprecated use method taking ASN1ObjectIdentifier 
		public virtual void addExtension(string OID, bool critical, byte[] value)
		{
			extGenerator.addExtension(new ASN1ObjectIdentifier(OID), critical, value);
		}

		/// <summary>
		/// add a given extension field for the standard extensions tag (tag 3) </summary>
		/// <exception cref="TSPIOException"> </exception>
		public virtual void addExtension(ASN1ObjectIdentifier oid, bool isCritical, ASN1Encodable value)
		{
			TSPUtil.addExtension(extGenerator, oid, isCritical, value);
		}

		/// <summary>
		/// add a given extension field for the standard extensions tag
		/// The value parameter becomes the contents of the octet string associated
		/// with the extension.
		/// </summary>
		public virtual void addExtension(ASN1ObjectIdentifier oid, bool isCritical, byte[] value)
		{
			extGenerator.addExtension(oid, isCritical, value);
		}

		/// @deprecated use method taking ANS1ObjectIdentifier 
		public virtual TimeStampRequest generate(string digestAlgorithm, byte[] digest)
		{
			return this.generate(digestAlgorithm, digest, null);
		}

		/// @deprecated use method taking ANS1ObjectIdentifier 
		public virtual TimeStampRequest generate(string digestAlgorithmOID, byte[] digest, BigInteger nonce)
		{
			if (string.ReferenceEquals(digestAlgorithmOID, null))
			{
				throw new IllegalArgumentException("No digest algorithm specified");
			}

			ASN1ObjectIdentifier digestAlgOID = new ASN1ObjectIdentifier(digestAlgorithmOID);

			AlgorithmIdentifier algID = new AlgorithmIdentifier(digestAlgOID, DERNull.INSTANCE);
			MessageImprint messageImprint = new MessageImprint(algID, digest);

			Extensions ext = null;

			if (!extGenerator.isEmpty())
			{
				ext = extGenerator.generate();
			}

			if (nonce != null)
			{
				return new TimeStampRequest(new TimeStampReq(messageImprint, reqPolicy, new ASN1Integer(nonce), certReq, ext));
			}
			else
			{
				return new TimeStampRequest(new TimeStampReq(messageImprint, reqPolicy, null, certReq, ext));
			}
		}

		public virtual TimeStampRequest generate(ASN1ObjectIdentifier digestAlgorithm, byte[] digest)
		{
			return generate(digestAlgorithm.getId(), digest);
		}

		public virtual TimeStampRequest generate(ASN1ObjectIdentifier digestAlgorithm, byte[] digest, BigInteger nonce)
		{
			return generate(digestAlgorithm.getId(), digest, nonce);
		}
	}

}