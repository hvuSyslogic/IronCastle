using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;

	/// <summary>
	/// PKIX RFC-2459
	/// 
	/// The X.509 v2 CRL syntax is as follows.  For signature calculation,
	/// the data that is to be signed is ASN.1 DER encoded.
	/// 
	/// <pre>
	/// CertificateList  ::=  SEQUENCE  {
	///      tbsCertList          TBSCertList,
	///      signatureAlgorithm   AlgorithmIdentifier,
	///      signatureValue       BIT STRING  }
	/// </pre>
	/// </summary>
	public class CertificateList : ASN1Object
	{
		internal TBSCertList tbsCertList;
		internal AlgorithmIdentifier sigAlgId;
		internal DERBitString sig;
		internal bool isHashCodeSet = false;
		internal int hashCodeValue;

		public static CertificateList getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static CertificateList getInstance(object obj)
		{
			if (obj is CertificateList)
			{
				return (CertificateList)obj;
			}
			else if (obj != null)
			{
				return new CertificateList(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		/// @deprecated use getInstance() method. 
		/// <param name="seq"> </param>
		public CertificateList(ASN1Sequence seq)
		{
			if (seq.size() == 3)
			{
				tbsCertList = TBSCertList.getInstance(seq.getObjectAt(0));
				sigAlgId = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
				sig = DERBitString.getInstance(seq.getObjectAt(2));
			}
			else
			{
				throw new IllegalArgumentException("sequence wrong size for CertificateList");
			}
		}

		public virtual TBSCertList getTBSCertList()
		{
			return tbsCertList;
		}

		public virtual TBSCertList.CRLEntry[] getRevokedCertificates()
		{
			return tbsCertList.getRevokedCertificates();
		}

		public virtual Enumeration getRevokedCertificateEnumeration()
		{
			return tbsCertList.getRevokedCertificateEnumeration();
		}

		public virtual AlgorithmIdentifier getSignatureAlgorithm()
		{
			return sigAlgId;
		}

		public virtual DERBitString getSignature()
		{
			return sig;
		}

		public virtual int getVersionNumber()
		{
			return tbsCertList.getVersionNumber();
		}

		public virtual X500Name getIssuer()
		{
			return tbsCertList.getIssuer();
		}

		public virtual Time getThisUpdate()
		{
			return tbsCertList.getThisUpdate();
		}

		public virtual Time getNextUpdate()
		{
			return tbsCertList.getNextUpdate();
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(tbsCertList);
			v.add(sigAlgId);
			v.add(sig);

			return new DERSequence(v);
		}

		public override int GetHashCode()
		{
			if (!isHashCodeSet)
			{
				hashCodeValue = base.GetHashCode();
				isHashCodeSet = true;
			}

			return hashCodeValue;
		}
	}

}