namespace org.bouncycastle.cert.path.validations
{

	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using Memoable = org.bouncycastle.util.Memoable;
	using Selector = org.bouncycastle.util.Selector;
	using Store = org.bouncycastle.util.Store;

	public class CRLValidation : CertPathValidation
	{
		private Store crls;
		private X500Name workingIssuerName;

		public CRLValidation(X500Name trustAnchorName, Store crls)
		{
			this.workingIssuerName = trustAnchorName;
			this.crls = crls;
		}

		public virtual void validate(CertPathValidationContext context, X509CertificateHolder certificate)
		{
			// TODO: add handling of delta CRLs
			Collection matches = crls.getMatches(new SelectorAnonymousInnerClass(this));

			if (matches.isEmpty())
			{
				throw new CertPathValidationException("CRL for " + workingIssuerName + " not found");
			}

			for (Iterator it = matches.iterator(); it.hasNext();)
			{
				X509CRLHolder crl = (X509CRLHolder)it.next();

				// TODO: not quite right!
				if (crl.getRevokedCertificate(certificate.getSerialNumber()) != null)
				{
					throw new CertPathValidationException("Certificate revoked");
				}
			}

			this.workingIssuerName = certificate.getSubject();
		}

		public class SelectorAnonymousInnerClass : Selector
		{
			private readonly CRLValidation outerInstance;

			public SelectorAnonymousInnerClass(CRLValidation outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			public bool match(object obj)
			{
				X509CRLHolder crl = (X509CRLHolder)obj;

				return (crl.getIssuer().Equals(outerInstance.workingIssuerName));
			}

			public object clone()
			{
				return this;
			}
		}

		public virtual Memoable copy()
		{
			return new CRLValidation(workingIssuerName, crls);
		}

		public virtual void reset(Memoable other)
		{
			CRLValidation v = (CRLValidation)other;

			this.workingIssuerName = v.workingIssuerName;
			this.crls = v.crls;
		}
	}

}