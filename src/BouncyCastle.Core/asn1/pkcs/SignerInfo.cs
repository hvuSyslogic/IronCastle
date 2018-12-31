using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.pkcs
{

	
	/// <summary>
	/// a PKCS#7 signer info object.
	/// </summary>
	public class SignerInfo : ASN1Object
	{
		private ASN1Integer version;
		private IssuerAndSerialNumber issuerAndSerialNumber;
		private AlgorithmIdentifier digAlgorithm;
		private ASN1Set authenticatedAttributes;
		private AlgorithmIdentifier digEncryptionAlgorithm;
		private ASN1OctetString encryptedDigest;
		private ASN1Set unauthenticatedAttributes;

		public static SignerInfo getInstance(object o)
		{
			if (o is SignerInfo)
			{
				return (SignerInfo)o;
			}
			else if (o is ASN1Sequence)
			{
				return new SignerInfo((ASN1Sequence)o);
			}

			throw new IllegalArgumentException("unknown object in factory: " + o.GetType().getName());
		}

		public SignerInfo(ASN1Integer version, IssuerAndSerialNumber issuerAndSerialNumber, AlgorithmIdentifier digAlgorithm, ASN1Set authenticatedAttributes, AlgorithmIdentifier digEncryptionAlgorithm, ASN1OctetString encryptedDigest, ASN1Set unauthenticatedAttributes)
		{
			this.version = version;
			this.issuerAndSerialNumber = issuerAndSerialNumber;
			this.digAlgorithm = digAlgorithm;
			this.authenticatedAttributes = authenticatedAttributes;
			this.digEncryptionAlgorithm = digEncryptionAlgorithm;
			this.encryptedDigest = encryptedDigest;
			this.unauthenticatedAttributes = unauthenticatedAttributes;
		}

		public SignerInfo(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();

			version = (ASN1Integer)e.nextElement();
			issuerAndSerialNumber = IssuerAndSerialNumber.getInstance(e.nextElement());
			digAlgorithm = AlgorithmIdentifier.getInstance(e.nextElement());

			object obj = e.nextElement();

			if (obj is ASN1TaggedObject)
			{
				authenticatedAttributes = ASN1Set.getInstance((ASN1TaggedObject)obj, false);

				digEncryptionAlgorithm = AlgorithmIdentifier.getInstance(e.nextElement());
			}
			else
			{
				authenticatedAttributes = null;
				digEncryptionAlgorithm = AlgorithmIdentifier.getInstance(obj);
			}

			encryptedDigest = DEROctetString.getInstance(e.nextElement());

			if (e.hasMoreElements())
			{
				unauthenticatedAttributes = ASN1Set.getInstance((ASN1TaggedObject)e.nextElement(), false);
			}
			else
			{
				unauthenticatedAttributes = null;
			}
		}

		public virtual ASN1Integer getVersion()
		{
			return version;
		}

		public virtual IssuerAndSerialNumber getIssuerAndSerialNumber()
		{
			return issuerAndSerialNumber;
		}

		public virtual ASN1Set getAuthenticatedAttributes()
		{
			return authenticatedAttributes;
		}

		public virtual AlgorithmIdentifier getDigestAlgorithm()
		{
			return digAlgorithm;
		}

		public virtual ASN1OctetString getEncryptedDigest()
		{
			return encryptedDigest;
		}

		public virtual AlgorithmIdentifier getDigestEncryptionAlgorithm()
		{
			return digEncryptionAlgorithm;
		}

		public virtual ASN1Set getUnauthenticatedAttributes()
		{
			return unauthenticatedAttributes;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		///  SignerInfo ::= SEQUENCE {
		///      version Version,
		///      issuerAndSerialNumber IssuerAndSerialNumber,
		///      digestAlgorithm DigestAlgorithmIdentifier,
		///      authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL,
		///      digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
		///      encryptedDigest EncryptedDigest,
		///      unauthenticatedAttributes [1] IMPLICIT Attributes OPTIONAL
		///  }
		/// 
		///  EncryptedDigest ::= OCTET STRING
		/// 
		///  DigestAlgorithmIdentifier ::= AlgorithmIdentifier
		/// 
		///  DigestEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(version);
			v.add(issuerAndSerialNumber);
			v.add(digAlgorithm);

			if (authenticatedAttributes != null)
			{
				v.add(new DERTaggedObject(false, 0, authenticatedAttributes));
			}

			v.add(digEncryptionAlgorithm);
			v.add(encryptedDigest);

			if (unauthenticatedAttributes != null)
			{
				v.add(new DERTaggedObject(false, 1, unauthenticatedAttributes));
			}

			return new DERSequence(v);
		}
	}

}