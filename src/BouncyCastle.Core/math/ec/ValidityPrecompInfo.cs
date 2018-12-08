namespace org.bouncycastle.math.ec
{
	public class ValidityPrecompInfo : PreCompInfo
	{
		internal const string PRECOMP_NAME = "bc_validity";

		private bool failed = false;
		private bool curveEquationPassed = false;
		private bool orderPassed = false;

		public virtual bool hasFailed()
		{
			return failed;
		}

		public virtual void reportFailed()
		{
			failed = true;
		}

		public virtual bool hasCurveEquationPassed()
		{
			return curveEquationPassed;
		}

		public virtual void reportCurveEquationPassed()
		{
			curveEquationPassed = true;
		}

		public virtual bool hasOrderPassed()
		{
			return orderPassed;
		}

		public virtual void reportOrderPassed()
		{
			orderPassed = true;
		}
	}

}