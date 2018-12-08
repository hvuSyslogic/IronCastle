using System.IO;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;

	/// <summary>
	/// <pre>
	///   CertificationRequest ::= SEQUENCE {
	///     certificationRequestInfo  SEQUENCE {
	///       version                   INTEGER,
	///       subject                   Name,
	///       subjectPublicKeyInfo      SEQUENCE {
	///          algorithm                 AlgorithmIdentifier,
	///          subjectPublicKey          BIT STRING },
	///       attributes                [0] IMPLICIT SET OF Attribute },
	///    signatureAlgorithm        AlgorithmIdentifier,
	///    signature                 BIT STRING
	///  }
	/// </pre>
	/// </summary>
	public class CertificationRequest : ASN1Object
	{
		private static readonly ASN1Integer ZERO = new ASN1Integer(0);

		private readonly CertificationRequestInfo certificationRequestInfo;
		private readonly AlgorithmIdentifier signatureAlgorithm;
		private readonly DERBitString signature;

		public CertificationRequest(X500Name subject, AlgorithmIdentifier subjectPublicAlgorithm, DERBitString subjectPublicKey, ASN1Set attributes, AlgorithmIdentifier signatureAlgorithm, DERBitString signature)
		{
			this.certificationRequestInfo = new CertificationRequestInfo(this, subject, subjectPublicAlgorithm, subjectPublicKey, attributes);
			this.signatureAlgorithm = signatureAlgorithm;
			this.signature = signature;
		}

		private CertificationRequest(ASN1Sequence seq)
		{
			if (seq.size() != 3)
			{
				throw new IllegalArgumentException("incorrect sequence size");
			}
			this.certificationRequestInfo = new CertificationRequestInfo(this, ASN1Sequence.getInstance(seq.getObjectAt(0)));
			this.signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
			this.signature = DERBitString.getInstance(seq.getObjectAt(2));
		}

		public static CertificationRequest getInstance(object o)
		{
			if (o is CertificationRequest)
			{
				return (CertificationRequest)o;
			}

			if (o != null)
			{
				return new CertificationRequest(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual BigInteger getVersion()
		{
			return certificationRequestInfo.getVersion().getValue();
		}

		public virtual X500Name getSubject()
		{
			return certificationRequestInfo.getSubject();
		}

		public virtual ASN1Set getAttributes()
		{
			return certificationRequestInfo.getAttributes();
		}

		public virtual AlgorithmIdentifier getSubjectPublicKeyAlgorithm()
		{
			return AlgorithmIdentifier.getInstance(certificationRequestInfo.getSubjectPublicKeyInfo().getObjectAt(0));
		}

		public virtual DERBitString getSubjectPublicKey()
		{
			return DERBitString.getInstance(certificationRequestInfo.getSubjectPublicKeyInfo().getObjectAt(1));
		}

		/// <summary>
		/// If the public key is an encoded object this will return the ASN.1 primitives encoded - if the bitstring
		/// can't be decoded this routine throws an IOException.
		/// </summary>
		/// <exception cref="IOException"> - if the bit string doesn't represent a DER encoded object. </exception>
		/// <returns> the public key as an ASN.1 primitive. </returns>
		public virtual ASN1Primitive parsePublicKey()
		{
			return ASN1Primitive.fromByteArray(getSubjectPublicKey().getOctets());
		}

		public virtual AlgorithmIdentifier getSignatureAlgorithm()
		{
			return signatureAlgorithm;
		}

		public virtual DERBitString getSignature()
		{
			return signature;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(certificationRequestInfo);
			v.add(signatureAlgorithm);
			v.add(signature);

			return new DERSequence(v);
		}

		public class CertificationRequestInfo : ASN1Object
		{
			private readonly CertificationRequest outerInstance;

			internal readonly ASN1Integer version;
			internal readonly X500Name subject;
			internal readonly ASN1Sequence subjectPublicKeyInfo;
			internal readonly ASN1Set attributes;

			public CertificationRequestInfo(CertificationRequest outerInstance, ASN1Sequence seq)
			{
				this.outerInstance = outerInstance;
				if (seq.size() != 4)
				{
					throw new IllegalArgumentException("incorrect sequence size for CertificationRequestInfo");
				}
				version = ASN1Integer.getInstance(seq.getObjectAt(0));

				subject = X500Name.getInstance(seq.getObjectAt(1));
				subjectPublicKeyInfo = ASN1Sequence.getInstance(seq.getObjectAt(2));
				if (subjectPublicKeyInfo.size() != 2)
				{
					throw new IllegalArgumentException("incorrect subjectPublicKeyInfo size for CertificationRequestInfo");
				}

				ASN1TaggedObject tagobj = (ASN1TaggedObject)seq.getObjectAt(3);
				if (tagobj.getTagNo() != 0)
				{
					throw new IllegalArgumentException("incorrect tag number on attributes for CertificationRequestInfo");
				}
				attributes = ASN1Set.getInstance(tagobj, false);
			}

			public CertificationRequestInfo(CertificationRequest outerInstance, X500Name subject, AlgorithmIdentifier algorithm, DERBitString subjectPublicKey, ASN1Set attributes)
			{
				this.outerInstance = outerInstance;
				this.version = ZERO;
				this.subject = subject;
				this.subjectPublicKeyInfo = new DERSequence(new ASN1Encodable[] {algorithm, subjectPublicKey});
				this.attributes = attributes;
			}

			public virtual ASN1Integer getVersion()
			{
				return version;
			}

			public virtual X500Name getSubject()
			{
				return subject;
			}

			public virtual ASN1Sequence getSubjectPublicKeyInfo()
			{
				return subjectPublicKeyInfo;
			}

			public virtual ASN1Set getAttributes()
			{
				return attributes;
			}

			public override ASN1Primitive toASN1Primitive()
			{
				ASN1EncodableVector v = new ASN1EncodableVector();

				v.add(version);
				v.add(subject);
				v.add(subjectPublicKeyInfo);
				v.add(new DERTaggedObject(false, 0, attributes));

				return new DERSequence(v);
			}
		}
	}

}