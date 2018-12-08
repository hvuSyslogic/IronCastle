namespace org.bouncycastle.cert.path.validations
{
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using KeyUsage = org.bouncycastle.asn1.x509.KeyUsage;
	using Memoable = org.bouncycastle.util.Memoable;

	public class KeyUsageValidation : CertPathValidation
	{
		private bool isMandatory;

		public KeyUsageValidation() : this(true)
		{
		}

		public KeyUsageValidation(bool isMandatory)
		{
			this.isMandatory = isMandatory;
		}

		public virtual void validate(CertPathValidationContext context, X509CertificateHolder certificate)
		{
			context.addHandledExtension(Extension.keyUsage);

			if (!context.isEndEntity())
			{
				KeyUsage usage = KeyUsage.fromExtensions(certificate.getExtensions());

				if (usage != null)
				{
					if (!usage.hasUsages(KeyUsage.keyCertSign))
					{
						throw new CertPathValidationException("Issuer certificate KeyUsage extension does not permit key signing");
					}
				}
				else
				{
					if (isMandatory)
					{
						throw new CertPathValidationException("KeyUsage extension not present in CA certificate");
					}
				}
			}
		}

		public virtual Memoable copy()
		{
			return new KeyUsageValidation(isMandatory);
		}

		public virtual void reset(Memoable other)
		{
			KeyUsageValidation v = (KeyUsageValidation)other;

			this.isMandatory = v.isMandatory;
		}
	}

}