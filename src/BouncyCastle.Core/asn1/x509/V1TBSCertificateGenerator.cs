using org.bouncycastle.Port;

namespace org.bouncycastle.asn1.x509
{
	using X500Name = org.bouncycastle.asn1.x500.X500Name;

	/// <summary>
	/// Generator for Version 1 TBSCertificateStructures.
	/// <pre>
	/// TBSCertificate ::= SEQUENCE {
	///      version          [ 0 ]  Version DEFAULT v1(0),
	///      serialNumber            CertificateSerialNumber,
	///      signature               AlgorithmIdentifier,
	///      issuer                  Name,
	///      validity                Validity,
	///      subject                 Name,
	///      subjectPublicKeyInfo    SubjectPublicKeyInfo,
	///      }
	/// </pre>
	/// 
	/// </summary>
	public class V1TBSCertificateGenerator
	{
		internal DERTaggedObject version = new DERTaggedObject(true, 0, new ASN1Integer(0));

		internal ASN1Integer serialNumber;
		internal AlgorithmIdentifier signature;
		internal X500Name issuer;
		internal Time startDate, endDate;
		internal X500Name subject;
		internal SubjectPublicKeyInfo subjectPublicKeyInfo;

		public V1TBSCertificateGenerator()
		{
		}

		public virtual void setSerialNumber(ASN1Integer serialNumber)
		{
			this.serialNumber = serialNumber;
		}

		public virtual void setSignature(AlgorithmIdentifier signature)
		{
			this.signature = signature;
		}

			/// @deprecated use X500Name method 
		public virtual void setIssuer(X509Name issuer)
		{
			this.issuer = X500Name.getInstance(issuer.toASN1Primitive());
		}

		public virtual void setIssuer(X500Name issuer)
		{
			this.issuer = issuer;
		}

		public virtual void setStartDate(Time startDate)
		{
			this.startDate = startDate;
		}

		public virtual void setStartDate(ASN1UTCTime startDate)
		{
			this.startDate = new Time(startDate);
		}

		public virtual void setEndDate(Time endDate)
		{
			this.endDate = endDate;
		}

		public virtual void setEndDate(ASN1UTCTime endDate)
		{
			this.endDate = new Time(endDate);
		}

		/// @deprecated use X500Name method 
		public virtual void setSubject(X509Name subject)
		{
			this.subject = X500Name.getInstance(subject.toASN1Primitive());
		}

		public virtual void setSubject(X500Name subject)
		{
			this.subject = subject;
		}

		public virtual void setSubjectPublicKeyInfo(SubjectPublicKeyInfo pubKeyInfo)
		{
			this.subjectPublicKeyInfo = pubKeyInfo;
		}

		public virtual TBSCertificate generateTBSCertificate()
		{
			if ((serialNumber == null) || (signature == null) || (issuer == null) || (startDate == null) || (endDate == null) || (subject == null) || (subjectPublicKeyInfo == null))
			{
				throw new IllegalStateException("not all mandatory fields set in V1 TBScertificate generator");
			}

			ASN1EncodableVector seq = new ASN1EncodableVector();

			// seq.add(version); - not required as default value.
			seq.add(serialNumber);
			seq.add(signature);
			seq.add(issuer);

			//
			// before and after dates
			//
			ASN1EncodableVector validity = new ASN1EncodableVector();

			validity.add(startDate);
			validity.add(endDate);

			seq.add(new DERSequence(validity));

			seq.add(subject);

			seq.add(subjectPublicKeyInfo);

			return TBSCertificate.getInstance(new DERSequence(seq));
		}
	}

}