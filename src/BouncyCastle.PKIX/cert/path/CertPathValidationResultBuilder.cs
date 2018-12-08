namespace org.bouncycastle.cert.path
{

	using Integers = org.bouncycastle.util.Integers;

	public class CertPathValidationResultBuilder
	{
		private readonly CertPathValidationContext context;
		private readonly List<int> certIndexes = new ArrayList<int>();
		private readonly List<int> ruleIndexes = new ArrayList<int>();
		private readonly List<CertPathValidationException> exceptions = new ArrayList<CertPathValidationException>();

		public CertPathValidationResultBuilder(CertPathValidationContext context)
		{
			this.context = context;
		}

		public virtual CertPathValidationResult build()
		{
			if (exceptions.isEmpty())
			{
				return new CertPathValidationResult(context);
			}
			else
			{
				return new CertPathValidationResult(context, toInts(certIndexes), toInts(ruleIndexes), (CertPathValidationException[])exceptions.toArray(new CertPathValidationException[exceptions.size()]));
			}
		}

		public virtual void addException(int certIndex, int ruleIndex, CertPathValidationException exception)
		{
			this.certIndexes.add(Integers.valueOf(certIndex));
			this.ruleIndexes.add(Integers.valueOf(ruleIndex));
			this.exceptions.add(exception);
		}

		private int[] toInts(List<int> values)
		{
			int[] rv = new int[values.size()];

			for (int i = 0; i != rv.Length; i++)
			{
				rv[i] = ((int?)values.get(i)).Value;
			}

			return rv;
		}
	}

}