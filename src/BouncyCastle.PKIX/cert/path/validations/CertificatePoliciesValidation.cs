namespace org.bouncycastle.cert.path.validations
{

	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using PolicyConstraints = org.bouncycastle.asn1.x509.PolicyConstraints;
	using Memoable = org.bouncycastle.util.Memoable;

	public class CertificatePoliciesValidation : CertPathValidation
	{
		private int explicitPolicy;
		private int policyMapping;
		private int inhibitAnyPolicy;

		public CertificatePoliciesValidation(int pathLength) : this(pathLength, false, false, false)
		{
		}

		public CertificatePoliciesValidation(int pathLength, bool isExplicitPolicyRequired, bool isAnyPolicyInhibited, bool isPolicyMappingInhibited)
		{
			//
			// (d)
			//

			if (isExplicitPolicyRequired)
			{
				explicitPolicy = 0;
			}
			else
			{
				explicitPolicy = pathLength + 1;
			}

			//
			// (e)
			//
			if (isAnyPolicyInhibited)
			{
				inhibitAnyPolicy = 0;
			}
			else
			{
				inhibitAnyPolicy = pathLength + 1;
			}

			//
			// (f)
			//
			if (isPolicyMappingInhibited)
			{
				policyMapping = 0;
			}
			else
			{
				policyMapping = pathLength + 1;
			}
		}

		public virtual void validate(CertPathValidationContext context, X509CertificateHolder certificate)
		{
			context.addHandledExtension(Extension.policyConstraints);
			context.addHandledExtension(Extension.inhibitAnyPolicy);

			if (!context.isEndEntity())
			{
				if (!ValidationUtils.isSelfIssued(certificate))
				{
					 //
					// H (1), (2), (3)
					//
					explicitPolicy = countDown(explicitPolicy);
					policyMapping = countDown(policyMapping);
					inhibitAnyPolicy = countDown(inhibitAnyPolicy);

					//
					// I (1), (2)
					//
					PolicyConstraints policyConstraints = PolicyConstraints.fromExtensions(certificate.getExtensions());

					if (policyConstraints != null)
					{
						BigInteger requireExplicitPolicyMapping = policyConstraints.getRequireExplicitPolicyMapping();
						if (requireExplicitPolicyMapping != null)
						{
							if (requireExplicitPolicyMapping.intValue() < explicitPolicy)
							{
								explicitPolicy = requireExplicitPolicyMapping.intValue();
							}
						}

						BigInteger inhibitPolicyMapping = policyConstraints.getInhibitPolicyMapping();
						if (inhibitPolicyMapping != null)
						{
							if (inhibitPolicyMapping.intValue() < policyMapping)
							{
								policyMapping = inhibitPolicyMapping.intValue();
							}
						}
					}

					//
					// J
					//
					Extension ext = certificate.getExtension(Extension.inhibitAnyPolicy);

					if (ext != null)
					{
						int extValue = ASN1Integer.getInstance(ext.getParsedValue()).getValue().intValue();

						if (extValue < inhibitAnyPolicy)
						{
							inhibitAnyPolicy = extValue;
						}
					}
				}
			}
		}

		private int countDown(int policyCounter)
		{
			if (policyCounter != 0)
			{
				return policyCounter - 1;
			}

			return 0;
		}

		public virtual Memoable copy()
		{
			return new CertificatePoliciesValidation(0); // TODO:
		}

		public virtual void reset(Memoable other)
		{
			CertificatePoliciesValidation v = (CertificatePoliciesValidation)other; // TODO:
		}
	}

}