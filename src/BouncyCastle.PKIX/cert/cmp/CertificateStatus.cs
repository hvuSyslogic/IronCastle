namespace org.bouncycastle.cert.cmp
{

	using CertStatus = org.bouncycastle.asn1.cmp.CertStatus;
	using PKIStatusInfo = org.bouncycastle.asn1.cmp.PKIStatusInfo;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DigestAlgorithmIdentifierFinder = org.bouncycastle.@operator.DigestAlgorithmIdentifierFinder;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using Arrays = org.bouncycastle.util.Arrays;

	public class CertificateStatus
	{
		private DigestAlgorithmIdentifierFinder digestAlgFinder;
		private CertStatus certStatus;

		public CertificateStatus(DigestAlgorithmIdentifierFinder digestAlgFinder, CertStatus certStatus)
		{
			this.digestAlgFinder = digestAlgFinder;
			this.certStatus = certStatus;
		}

		public virtual PKIStatusInfo getStatusInfo()
		{
			return certStatus.getStatusInfo();
		}

		public virtual BigInteger getCertRequestID()
		{
			return certStatus.getCertReqId().getValue();
		}

		public virtual bool isVerified(X509CertificateHolder certHolder, DigestCalculatorProvider digesterProvider)
		{
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
				throw new CMPException("unable to create digester: " + e.Message, e);
			}

			CMPUtil.derEncodeToStream(certHolder.toASN1Structure(), digester.getOutputStream());

			return Arrays.areEqual(certStatus.getCertHash().getOctets(), digester.getDigest());
		}
	}

}