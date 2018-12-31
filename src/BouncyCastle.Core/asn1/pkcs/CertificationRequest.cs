using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.pkcs
{
	
	/// <summary>
	/// PKCS10 Certification request object.
	/// <pre>
	/// CertificationRequest ::= SEQUENCE {
	///   certificationRequestInfo  CertificationRequestInfo,
	///   signatureAlgorithm        AlgorithmIdentifier{{ SignatureAlgorithms }},
	///   signature                 BIT STRING
	/// }
	/// </pre>
	/// </summary>
	public class CertificationRequest : ASN1Object
	{
		protected internal CertificationRequestInfo reqInfo = null;
		protected internal AlgorithmIdentifier sigAlgId = null;
		protected internal DERBitString sigBits = null;

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

		public CertificationRequest()
		{
		}

		public CertificationRequest(CertificationRequestInfo requestInfo, AlgorithmIdentifier algorithm, DERBitString signature)
		{
			this.reqInfo = requestInfo;
			this.sigAlgId = algorithm;
			this.sigBits = signature;
		}

		/// @deprecated use getInstance() 
		public CertificationRequest(ASN1Sequence seq)
		{
			reqInfo = CertificationRequestInfo.getInstance(seq.getObjectAt(0));
			sigAlgId = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
			sigBits = (DERBitString)seq.getObjectAt(2);
		}

		public virtual CertificationRequestInfo getCertificationRequestInfo()
		{
			return reqInfo;
		}

		public virtual AlgorithmIdentifier getSignatureAlgorithm()
		{
			return sigAlgId;
		}

		public virtual DERBitString getSignature()
		{
			return sigBits;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			// Construct the CertificateRequest
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(reqInfo);
			v.add(sigAlgId);
			v.add(sigBits);

			return new DERSequence(v);
		}
	}

}