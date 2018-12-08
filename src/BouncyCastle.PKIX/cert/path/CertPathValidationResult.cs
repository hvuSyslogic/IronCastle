namespace org.bouncycastle.cert.path
{

	using Arrays = org.bouncycastle.util.Arrays;

	public class CertPathValidationResult
	{
//JAVA TO C# CONVERTER NOTE: Fields cannot have the same name as methods:
		private readonly bool isValid_Renamed;
		private readonly CertPathValidationException cause;
		private readonly Set unhandledCriticalExtensionOIDs;
		private readonly int certIndex;
		private readonly int ruleIndex;

		private CertPathValidationException[] causes;
		private int[] certIndexes;
		private int[] ruleIndexes;

		public CertPathValidationResult(CertPathValidationContext context)
		{
			this.unhandledCriticalExtensionOIDs = Collections.unmodifiableSet(context.getUnhandledCriticalExtensionOIDs());
			this.isValid_Renamed = this.unhandledCriticalExtensionOIDs.isEmpty();
			this.certIndex = -1;
			this.ruleIndex = -1;
			cause = null;
		}

		public CertPathValidationResult(CertPathValidationContext context, int certIndex, int ruleIndex, CertPathValidationException cause)
		{
			this.unhandledCriticalExtensionOIDs = Collections.unmodifiableSet(context.getUnhandledCriticalExtensionOIDs());
			this.isValid_Renamed = false;
			this.certIndex = certIndex;
			this.ruleIndex = ruleIndex;
			this.cause = cause;
		}

		public CertPathValidationResult(CertPathValidationContext context, int[] certIndexes, int[] ruleIndexes, CertPathValidationException[] causes)
		{
			this.unhandledCriticalExtensionOIDs = Collections.unmodifiableSet(context.getUnhandledCriticalExtensionOIDs());
			this.isValid_Renamed = false;
			this.cause = causes[0];
			this.certIndex = certIndexes[0];
			this.ruleIndex = ruleIndexes[0];
			this.causes = causes;
			this.certIndexes = certIndexes;
			this.ruleIndexes = ruleIndexes;
		}

		public virtual bool isValid()
		{
			return isValid_Renamed;
		}

		public virtual CertPathValidationException getCause()
		{
			if (cause != null)
			{
				return cause;
			}

			if (!unhandledCriticalExtensionOIDs.isEmpty())
			{
				return new CertPathValidationException("Unhandled Critical Extensions");
			}

			return null;
		}

		public virtual int getFailingCertIndex()
		{
			return certIndex;
		}

		public virtual int getFailingRuleIndex()
		{
			return ruleIndex;
		}

		public virtual Set getUnhandledCriticalExtensionOIDs()
		{
			return unhandledCriticalExtensionOIDs;
		}

		public virtual bool isDetailed()
		{
			return this.certIndexes != null;
		}

		public virtual CertPathValidationException[] getCauses()
		{
			if (causes != null)
			{
				CertPathValidationException[] rv = new CertPathValidationException[causes.Length];

				JavaSystem.arraycopy(causes, 0, rv, 0, causes.Length);

				return rv;
			}

			if (!unhandledCriticalExtensionOIDs.isEmpty())
			{
				return new CertPathValidationException[] {new CertPathValidationException("Unhandled Critical Extensions")};
			}

			return null;
		}

		public virtual int[] getFailingCertIndexes()
		{
			return Arrays.clone(certIndexes);
		}

		public virtual int[] getFailingRuleIndexes()
		{
			return Arrays.clone(ruleIndexes);
		}
	}

}