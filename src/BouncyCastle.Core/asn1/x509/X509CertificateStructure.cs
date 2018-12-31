using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.x500;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{
		
	/// <summary>
	/// an X509Certificate structure.
	/// <pre>
	///  Certificate ::= SEQUENCE {
	///      tbsCertificate          TBSCertificate,
	///      signatureAlgorithm      AlgorithmIdentifier,
	///      signature               BIT STRING
	///  }
	/// </pre> </summary>
	/// @deprecated use org.bouncycastle.asn1.x509.Certificate 
	public class X509CertificateStructure : ASN1Object, X509ObjectIdentifiers, PKCSObjectIdentifiers
	{
		internal ASN1Sequence seq;
		internal TBSCertificateStructure tbsCert;
		internal AlgorithmIdentifier sigAlgId;
		internal DERBitString sig;

		public static X509CertificateStructure getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static X509CertificateStructure getInstance(object obj)
		{
			if (obj is X509CertificateStructure)
			{
				return (X509CertificateStructure)obj;
			}
			else if (obj != null)
			{
				return new X509CertificateStructure(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public X509CertificateStructure(ASN1Sequence seq)
		{
			this.seq = seq;

			//
			// correct x509 certficate
			//
			if (seq.size() == 3)
			{
				tbsCert = TBSCertificateStructure.getInstance(seq.getObjectAt(0));
				sigAlgId = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));

				sig = DERBitString.getInstance(seq.getObjectAt(2));
			}
			else
			{
				throw new IllegalArgumentException("sequence wrong size for a certificate");
			}
		}

		public virtual TBSCertificateStructure getTBSCertificate()
		{
			return tbsCert;
		}

		public virtual int getVersion()
		{
			return tbsCert.getVersion();
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