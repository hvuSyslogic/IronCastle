namespace org.bouncycastle.cert.path
{

	public class CertPath
	{
		private readonly X509CertificateHolder[] certificates;

		public CertPath(X509CertificateHolder[] certificates)
		{
			this.certificates = copyArray(certificates);
		}

		public virtual X509CertificateHolder[] getCertificates()
		{
			return copyArray(certificates);
		}

		public virtual CertPathValidationResult validate(CertPathValidation[] ruleSet)
		{
			CertPathValidationContext context = new CertPathValidationContext(CertPathUtils.getCriticalExtensionsOIDs(certificates));

			for (int i = 0; i != ruleSet.Length; i++)
			{
				for (int j = certificates.Length - 1; j >= 0; j--)
				{
					try
					{
						context.setIsEndEntity(j == 0);
						ruleSet[i].validate(context, certificates[j]);
					}
					catch (CertPathValidationException e)
					{ // TODO: introduce object to hold (i and e)
						return new CertPathValidationResult(context, j, i, e);
					}
				}
			}

			return new CertPathValidationResult(context);
		}

		public virtual CertPathValidationResult evaluate(CertPathValidation[] ruleSet)
		{
			CertPathValidationContext context = new CertPathValidationContext(CertPathUtils.getCriticalExtensionsOIDs(certificates));

			CertPathValidationResultBuilder builder = new CertPathValidationResultBuilder(context);

			for (int i = 0; i != ruleSet.Length; i++)
			{
				for (int j = certificates.Length - 1; j >= 0; j--)
				{
					try
					{
						context.setIsEndEntity(j == 0);
						ruleSet[i].validate(context, certificates[j]);
					}
					catch (CertPathValidationException e)
					{
					   builder.addException(j, i, e);
					}
				}
			}

			return builder.build();
		}

		private X509CertificateHolder[] copyArray(X509CertificateHolder[] array)
		{
			X509CertificateHolder[] rv = new X509CertificateHolder[array.Length];

			JavaSystem.arraycopy(array, 0, rv, 0, rv.Length);

			return rv;
		}

		public virtual int length()
		{
			return certificates.Length;
		}
	}

}