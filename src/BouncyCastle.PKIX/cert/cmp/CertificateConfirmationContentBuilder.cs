namespace org.bouncycastle.cert.cmp
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using CertConfirmContent = org.bouncycastle.asn1.cmp.CertConfirmContent;
	using CertStatus = org.bouncycastle.asn1.cmp.CertStatus;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DefaultDigestAlgorithmIdentifierFinder = org.bouncycastle.@operator.DefaultDigestAlgorithmIdentifierFinder;
	using DigestAlgorithmIdentifierFinder = org.bouncycastle.@operator.DigestAlgorithmIdentifierFinder;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;

	public class CertificateConfirmationContentBuilder
	{
		private DigestAlgorithmIdentifierFinder digestAlgFinder;
		private List acceptedCerts = new ArrayList();
		private List acceptedReqIds = new ArrayList();

		public CertificateConfirmationContentBuilder() : this(new DefaultDigestAlgorithmIdentifierFinder())
		{
		}

		public CertificateConfirmationContentBuilder(DigestAlgorithmIdentifierFinder digestAlgFinder)
		{
			this.digestAlgFinder = digestAlgFinder;
		}

		public virtual CertificateConfirmationContentBuilder addAcceptedCertificate(X509CertificateHolder certHolder, BigInteger certReqID)
		{
			acceptedCerts.add(certHolder);
			acceptedReqIds.add(certReqID);

			return this;
		}

		public virtual CertificateConfirmationContent build(DigestCalculatorProvider digesterProvider)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			for (int i = 0; i != acceptedCerts.size(); i++)
			{
				X509CertificateHolder certHolder = (X509CertificateHolder)acceptedCerts.get(i);
				BigInteger reqID = (BigInteger)acceptedReqIds.get(i);

				AlgorithmIdentifier digAlg = digestAlgFinder.find(certHolder.toASN1Structure().getSignatureAlgorithm());
				if (digAlg == null)
				{
					throw new CMPException("cannot find algorithm for digest from signature");
				}

				DigestCalculator digester;

				try
				{
					digester = digesterProvider.get(digAlg);
				}
				catch (OperatorCreationException e)
				{
					throw new CMPException("unable to create digest: " + e.Message, e);
				}

				CMPUtil.derEncodeToStream(certHolder.toASN1Structure(), digester.getOutputStream());

				v.add(new CertStatus(digester.getDigest(), reqID));
			}

			return new CertificateConfirmationContent(CertConfirmContent.getInstance(new DERSequence(v)), digestAlgFinder);
		}

	}

}