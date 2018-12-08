namespace org.bouncycastle.cert.path.validations
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Null = org.bouncycastle.asn1.ASN1Null;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using Memoable = org.bouncycastle.util.Memoable;

	public class ParentCertIssuedValidation : CertPathValidation
	{
		private X509ContentVerifierProviderBuilder contentVerifierProvider;

		private X500Name workingIssuerName;
		private SubjectPublicKeyInfo workingPublicKey;
		private AlgorithmIdentifier workingAlgId;

		public ParentCertIssuedValidation(X509ContentVerifierProviderBuilder contentVerifierProvider)
		{
			this.contentVerifierProvider = contentVerifierProvider;
		}

		public virtual void validate(CertPathValidationContext context, X509CertificateHolder certificate)
		{
			if (workingIssuerName != null)
			{
			   if (!workingIssuerName.Equals(certificate.getIssuer()))
			   {
				   throw new CertPathValidationException("Certificate issue does not match parent");
			   }
			}

			if (workingPublicKey != null)
			{
				try
				{
					SubjectPublicKeyInfo validatingKeyInfo;

					if (workingPublicKey.getAlgorithm().Equals(workingAlgId))
					{
						validatingKeyInfo = workingPublicKey;
					}
					else
					{
						validatingKeyInfo = new SubjectPublicKeyInfo(workingAlgId, workingPublicKey.parsePublicKey());
					}

					if (!certificate.isSignatureValid(contentVerifierProvider.build(validatingKeyInfo)))
					{
						throw new CertPathValidationException("Certificate signature not for public key in parent");
					}
				}
				catch (OperatorCreationException e)
				{
					throw new CertPathValidationException("Unable to create verifier: " + e.Message, e);
				}
				catch (CertException e)
				{
					throw new CertPathValidationException("Unable to validate signature: " + e.Message, e);
				}
				catch (IOException e)
				{
					throw new CertPathValidationException("Unable to build public key: " + e.Message, e);
				}
			}

			workingIssuerName = certificate.getSubject();
			workingPublicKey = certificate.getSubjectPublicKeyInfo();

			if (workingAlgId != null)
			{
				// check for inherited parameters
				if (workingPublicKey.getAlgorithm().getAlgorithm().Equals(workingAlgId.getAlgorithm()))
				{
					if (!isNull(workingPublicKey.getAlgorithm().getParameters()))
					{
						workingAlgId = workingPublicKey.getAlgorithm();
					}
				}
				else
				{
					workingAlgId = workingPublicKey.getAlgorithm();
				}
			}
			else
			{
				workingAlgId = workingPublicKey.getAlgorithm();
			}
		}

		private bool isNull(ASN1Encodable obj)
		{
			return obj == null || obj is ASN1Null;
		}

		public virtual Memoable copy()
		{
			ParentCertIssuedValidation v = new ParentCertIssuedValidation(contentVerifierProvider);

			v.workingAlgId = this.workingAlgId;
			v.workingIssuerName = this.workingIssuerName;
			v.workingPublicKey = this.workingPublicKey;

			return v;
		}

		public virtual void reset(Memoable other)
		{
			ParentCertIssuedValidation v = (ParentCertIssuedValidation)other;

			this.contentVerifierProvider = v.contentVerifierProvider;
			this.workingAlgId = v.workingAlgId;
			this.workingIssuerName = v.workingIssuerName;
			this.workingPublicKey = v.workingPublicKey;
		}
	}

}