using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{
	using X500Name = org.bouncycastle.asn1.x500.X500Name;

	/// <summary>
	/// an X509Certificate structure.
	/// <pre>
	///  Certificate ::= SEQUENCE {
	///      tbsCertificate          TBSCertificate,
	///      signatureAlgorithm      AlgorithmIdentifier,
	///      signature               BIT STRING
	///  }
	/// </pre>
	/// </summary>
	public class Certificate : ASN1Object
	{
		internal ASN1Sequence seq;
		internal TBSCertificate tbsCert;
		internal AlgorithmIdentifier sigAlgId;
		internal DERBitString sig;

		public static Certificate getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static Certificate getInstance(object obj)
		{
			if (obj is Certificate)
			{
				return (Certificate)obj;
			}
			else if (obj != null)
			{
				return new Certificate(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private Certificate(ASN1Sequence seq)
		{
			this.seq = seq;

			//
			// correct x509 certficate
			//
			if (seq.size() == 3)
			{
				tbsCert = TBSCertificate.getInstance(seq.getObjectAt(0));
				sigAlgId = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));

				sig = DERBitString.getInstance(seq.getObjectAt(2));
			}
			else
			{
				throw new IllegalArgumentException("sequence wrong size for a certificate");
			}
		}

		public virtual TBSCertificate getTBSCertificate()
		{
			return tbsCert;
		}

		public virtual ASN1Integer getVersion()
		{
			return tbsCert.getVersion();
		}

		public virtual int getVersionNumber()
		{
			return tbsCert.getVersionNumber();
		}

		public virtual ASN1Integer getSerialNumber()
		{
			return tbsCert.getSerialNumber();
		}

		public virtual X500Name getIssuer()
		{
			return tbsCert.getIssuer();
		}

		public virtual Time getStartDate()
		{
			return tbsCert.getStartDate();
		}

		public virtual Time getEndDate()
		{
			return tbsCert.getEndDate();
		}

		public virtual X500Name getSubject()
		{
			return tbsCert.getSubject();
		}

		public virtual SubjectPublicKeyInfo getSubjectPublicKeyInfo()
		{
			return tbsCert.getSubjectPublicKeyInfo();
		}

		public virtual AlgorithmIdentifier getSignatureAlgorithm()
		{
			return sigAlgId;
		}

		public virtual DERBitString getSignature()
		{
			return sig;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return seq;
		}
	}

}